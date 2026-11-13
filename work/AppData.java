package com.gameloft.android.ANMP.GloftM4HM;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Application;
import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.os.Bundle;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Properties;

/** Bootstrap before providers; guard components before opening game data.
 * Bootstrap requires a cold, quiescent package. It never copies an open SQLite database.
 * Keep .phase5-original-* until cold/pause-resume proof; cleanup is intentionally external.
 */
public final class AppData extends Application {
    private static final String VERSION = "MC4_DATA_LINKS_V1";
    private static final String MARKER = ".phase5-data-links-v1";
    private static final String ARCHIVE = ".phase5-migration-archive";
    private static final String WEBVIEW = "app_webview";
    private static final String WEBVIEW_VERSION = "MC4_WEBVIEW_LINKS_V1";
    private static final String WEBVIEW_MARKER = ".phase5-webview-links-v1";
    private static final String[] GROUPS = {"files", "shared_prefs", "databases"};
    private static final String[] SAVES = {"SaveGame.bin", "CheckPoint.bin", "backupSaveFile.dat"};
    private static volatile File root;
    private static volatile String nativeAlias;
    private static volatile String startupError = "Game data bootstrap has not run.";

    @Override protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            initialize(base);
        } catch (Exception e) {
            root = null;
            nativeAlias = null;
            startupError = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    public static boolean ready() { return root != null && nativeAlias != null && startupError == null; }
    public static String error() { return startupError; }

    /** Call only after Activity.super.onCreate(), before game initialization; false means return.
     * Lifecycle callbacks, providers and receivers must separately return early when !ready().
     */
    public static boolean guard(final Activity activity) {
        if (ready()) return true;
        final AlertDialog dialog = new AlertDialog.Builder(activity, android.R.style.Theme_Material_Light_Dialog_Alert)
                .setTitle("Game data unavailable")
                .setMessage("Cannot open external game data. Existing data has been preserved.\n\n"
                        + startupError + "\n\nClose the game, restore storage access, and restart.")
                .setCancelable(false)
                .setPositiveButton(android.R.string.ok, (button, which) -> activity.finish())
                .create();
        final Application application = activity.getApplication();
        application.registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
            @Override public void onActivityCreated(Activity owner, Bundle state) { }
            @Override public void onActivityStarted(Activity owner) { }
            @Override public void onActivityResumed(Activity owner) { }
            @Override public void onActivityPaused(Activity owner) { }
            @Override public void onActivityStopped(Activity owner) { }
            @Override public void onActivitySaveInstanceState(Activity owner, Bundle state) { }
            @Override public void onActivityDestroyed(Activity owner) {
                if (owner == activity) {
                    dialog.dismiss();
                    application.unregisterActivityLifecycleCallbacks(this);
                }
            }
        });
        dialog.show();
        return false;
    }

    public static String externalFolder() { requireReady(); return root.getAbsolutePath(); }
    public static String nativeSaveFolder() { requireReady(); return nativeAlias; }
    public static String temporaryFolder() {
        requireReady();
        File cache = new File(root, "cache");
        try { directory(cache); } catch (IOException e) { throw new IllegalStateException(e); }
        return cache.getAbsolutePath();
    }

    public static void requireReady() {
        if (!ready()) throw new IllegalStateException(startupError);
    }

    /** This preserves the guest's literal /data/data fast path. Verify the alias against the
     * actual Context data directory; a different user/profile fails instead of falling back.
     */
    static synchronized void initialize(Context context) throws IOException {
        File data = context.getDataDir();
        File external = context.getExternalFilesDir(null);
        if (data == null || external == null) throw new IOException("External game directory is unavailable.");
        String alias = "/data/data/" + context.getPackageName() + "/files";
        if (!sameDirectory(new File(alias).getParentFile(), data))
            throw new IOException("Native save alias does not resolve to this app/user: " + alias);
        prepare(data, external);
        prepareWebView(data, external);
        if (!sameDirectory(new File(alias), external))
            throw new IOException("Native save alias does not resolve to external storage.");
        root = external.getCanonicalFile();
        nativeAlias = alias;
        startupError = null;
    }

    /** Package-private only for a filesystem host check. Real bootstrap always uses Context. */
    static void prepare(File data, File external) throws IOException {
        data = data.getCanonicalFile();
        external = external.getCanonicalFile();
        if (external.equals(data) || external.getPath().startsWith(data.getPath() + File.separator))
            throw new IOException("External root is inside private storage.");
        directory(data);
        directory(external);
        probeWritable(external);
        File lockPath = new File(data, ".phase5-data.lock");
        regularOrAbsent(lockPath);
        try (FileOutputStream lockStream = new FileOutputStream(lockPath, true);
             FileLock ignored = lockStream.getChannel().lock()) {
            probeLink(data, external);
            File privateMarker = new File(data, MARKER);
            File externalMarker = new File(external, MARKER);
            if (exists(privateMarker)) {
                verifyCompleted(data, external, read(privateMarker));
                return;
            }
            if (exists(externalMarker)) {
                // Recover the crash window between external and private marker commits.
                byte[] completed = read(externalMarker);
                verifyCompleted(data, external, completed);
                atomicWrite(privateMarker, completed);
                return;
            }
            Properties manifest = new Properties();
            manifest.setProperty("version", VERSION);
            manifest.setProperty("root", external.getPath());
            File archiveRoot = new File(external, ARCHIVE);
            directory(archiveRoot);
            for (String group : GROUPS) {
                File live = new File(data, group);
                File original = new File(data, ".phase5-original-" + group);
                File target = target(external, group);
                if (isLink(live)) {
                    verifyLink(live, target);
                    if (!exists(original)) throw new IOException("Missing retained original: " + original);
                } else {
                    if (exists(live) && exists(original))
                        throw new IOException("Both private live and original directories exist: " + group);
                    if (!exists(live) && !exists(original)) directory(live);
                }
                File source = exists(original) ? original : live;
                directory(source);
                File archived = new File(archiveRoot, group);
                copySnapshot(source, archived);
                String sourceHash = treeHash(source);
                if (!sourceHash.equals(treeHash(archived))) throw new IOException("Archive hash mismatch: " + group);
                manifest.setProperty("archive." + group, sourceHash);
                manifest.setProperty("original." + group, original.getPath());
                if (!isLink(live)) {
                    String mode;
                    if (group.equals("files")) {
                        int conflicts = mergeFiles(source, external);
                        mode = "files-merged;conflicts=" + conflicts;
                        if (conflicts != 0) { }
                    } else {
                        mode = stageDirectory(source, target, external, group);
                        if (mode.equals("external-kept"))
                            { }
                    }
                    manifest.setProperty("mode." + group, mode);
                    activate(live, original, target);
                } else {
                    manifest.setProperty("mode." + group, "recovered-link");
                }
                verifyLink(live, target);
            }
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            manifest.store(bytes, VERSION);
            byte[] completed = bytes.toByteArray();
            atomicWrite(externalMarker, completed);
            verifyCompleted(data, external, completed);
            atomicWrite(privateMarker, completed);
        }
    }

    /** The known Chromium profile includes persistent LevelDB/preferences. Run cold, before
     * any android.webkit owner, including Device's User-Agent probe. Keep the three-group V1
     * markers byte-for-byte unchanged; this profile has its own completion marker pair.
     */
    static void prepareWebView(File data, File external) throws IOException {
        data = data.getCanonicalFile();
        external = external.getCanonicalFile();
        for (File parent = external; parent != null; parent = parent.getParentFile()) {
            if (parent.getCanonicalFile().equals(data)) throw new IOException("External WebView directory is inside private storage.");
        }
        directory(data);
        directory(external);
        File lockPath = new File(data, ".phase5-data.lock");
        regularOrAbsent(lockPath);
        try (FileOutputStream lockStream = new FileOutputStream(lockPath, true);
             FileLock ignored = lockStream.getChannel().lock()) {
            File privateMarker = new File(data, WEBVIEW_MARKER);
            File externalMarker = new File(external, WEBVIEW_MARKER);
            if (exists(privateMarker)) {
                verifyWebViewCompleted(data, external, read(privateMarker));
                return;
            }
            if (exists(externalMarker)) {
                byte[] completed = read(externalMarker);
                verifyWebViewCompleted(data, external, completed);
                atomicWrite(privateMarker, completed);
                return;
            }
            File live = new File(data, WEBVIEW);
            File original = new File(data, ".phase5-original-" + WEBVIEW);
            File target = new File(external, WEBVIEW);
            if (isLink(live)) {
                verifyLink(live, target);
                if (!exists(original)) throw new IOException("Missing retained WebView original: " + original);
            } else {
                if (exists(live) && exists(original))
                    throw new IOException("Both private live and original WebView directories exist.");
                if (!exists(live) && !exists(original)) directory(live);
            }
            File source = exists(original) ? original : live;
            directory(source);
            File archiveRoot = new File(external, ARCHIVE);
            directory(archiveRoot);
            File archived = new File(archiveRoot, WEBVIEW);
            copySnapshot(source, archived);
            String sourceHash = treeHash(source);
            if (!sourceHash.equals(treeHash(archived))) throw new IOException("WebView archive hash mismatch.");
            String mode = "recovered-link";
            if (!isLink(live)) {
                mode = stageDirectory(source, target, external, WEBVIEW);
                if (mode.equals("external-kept"))
                    { }
                activate(live, original, target);
            }
            Properties manifest = new Properties();
            manifest.setProperty("version", WEBVIEW_VERSION);
            manifest.setProperty("root", external.getPath());
            manifest.setProperty("archive." + WEBVIEW, sourceHash);
            manifest.setProperty("original." + WEBVIEW, original.getPath());
            manifest.setProperty("mode." + WEBVIEW, mode);
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            manifest.store(bytes, WEBVIEW_VERSION);
            byte[] completed = bytes.toByteArray();
            atomicWrite(externalMarker, completed);
            verifyWebViewCompleted(data, external, completed);
            atomicWrite(privateMarker, completed);
        }
    }

    private static void verifyWebViewCompleted(File data, File external, byte[] expected) throws IOException {
        if (!Arrays.equals(expected, read(new File(external, WEBVIEW_MARKER))))
            throw new IOException("External WebView migration marker is missing or changed; storage restore is required.");
        Properties manifest = new Properties();
        manifest.load(new ByteArrayInputStream(expected));
        if (!WEBVIEW_VERSION.equals(manifest.getProperty("version")) || !external.getPath().equals(manifest.getProperty("root")))
            throw new IOException("Invalid WebView migration version/root.");
        File live = new File(data, WEBVIEW), target = new File(external, WEBVIEW);
        verifyLink(live, target);
        if (!sameDirectory(live, target)) throw new IOException("WebView alias does not resolve to external storage.");
        File archived = new File(new File(external, ARCHIVE), WEBVIEW);
        if (!treeHash(archived).equals(manifest.getProperty("archive." + WEBVIEW)))
            throw new IOException("WebView migration archive is incomplete/corrupt.");
    }

    static int mergeFiles(File source, File destination) throws IOException {
        boolean saveConflict = false;
        for (String name : SAVES) {
            File from = new File(source, name), to = new File(destination, name);
            if (exists(to) && (!exists(from) || !same(from, to))) saveConflict = true;
        }
        return merge(source, destination, source, saveConflict);
    }

    private static int merge(File source, File destination, File top, boolean saveConflict) throws IOException {
        directory(destination);
        int conflicts = 0;
        for (File from : children(source)) {
            File to = new File(destination, from.getName());
            if (isDirectory(from)) {
                if (exists(to) && !isDirectory(to)) { conflicts++; continue; }
                conflicts += merge(from, to, top, saveConflict);
            } else {
                regularOrAbsent(from);
                boolean save = from.getParentFile().equals(top) && Arrays.asList(SAVES).contains(from.getName());
                if (save && saveConflict) { conflicts++; continue; }
                if (exists(to)) { if (!same(from, to)) conflicts++; }
                else atomicCopy(from, to);
            }
        }
        return conflicts;
    }

    private static String stageDirectory(File source, File target, File external, String group) throws IOException {
        if (exists(target)) {
            directory(target);
            if (children(target).length != 0) return "external-kept";
        }
        File stage = new File(external, ".phase5-stage-" + group);
        copySnapshot(source, stage);
        if (!treeHash(source).equals(treeHash(stage))) throw new IOException("Stage hash mismatch: " + group);
        rename(stage, target); // Only absent/empty destination, while the package is quiescent.
        return "private-copied";
    }

    private static void activate(File live, File original, File target) throws IOException {
        File link = new File(live.getParentFile(), ".phase5-link-" + live.getName());
        if (exists(link)) verifyLink(link, target); else symlink(target, link);
        if (exists(live)) rename(live, original);
        if (!exists(original)) throw new IOException("No retained original for " + live);
        rename(link, live);
        verifyLink(live, target);
    }

    private static void verifyCompleted(File data, File external, byte[] expected) throws IOException {
        if (!Arrays.equals(expected, read(new File(external, MARKER))))
            throw new IOException("External migration marker is missing or changed; storage restore is required.");
        Properties manifest = new Properties();
        manifest.load(new ByteArrayInputStream(expected));
        if (!VERSION.equals(manifest.getProperty("version")) || !external.getPath().equals(manifest.getProperty("root")))
            throw new IOException("Invalid migration version/root.");
        for (String group : GROUPS) {
            verifyLink(new File(data, group), target(external, group));
            File archived = new File(new File(external, ARCHIVE), group);
            if (!treeHash(archived).equals(manifest.getProperty("archive." + group)))
                throw new IOException("Migration archive is incomplete/corrupt: " + group);
        }
    }

    static void copySnapshot(File source, File destination) throws IOException {
        directory(source);
        directory(destination);
        for (File from : children(source)) {
            File to = new File(destination, from.getName());
            if (isDirectory(from)) copySnapshot(from, to);
            else {
                regularOrAbsent(from);
                if (exists(to)) {
                    if (!same(from, to)) throw new IOException("Snapshot conflict; both copies retained: " + to);
                } else atomicCopy(from, to);
            }
        }
        if (!treeHash(source).equals(treeHash(destination))) throw new IOException("Snapshot inventory mismatch: " + destination);
    }

    static String treeHash(File directory) throws IOException {
        MessageDigest digest = sha256();
        inventory(directory, "", digest);
        return hex(digest.digest());
    }

    private static void inventory(File directory, String relative, MessageDigest digest) throws IOException {
        for (File entry : children(directory)) {
            String path = relative + entry.getName();
            if (path.indexOf('\n') >= 0 || path.indexOf('\r') >= 0 || path.indexOf('\t') >= 0)
                throw new IOException("Unsupported migration filename: " + entry);
            String row;
            if (isDirectory(entry)) {
                row = "D\t" + path + "\n";
                digest.update(row.getBytes(StandardCharsets.UTF_8));
                inventory(entry, path + "/", digest);
            } else {
                regularOrAbsent(entry);
                row = "F\t" + path + "\t" + entry.length() + "\t" + fileHash(entry) + "\n";
                digest.update(row.getBytes(StandardCharsets.UTF_8));
            }
        }
    }

    private static File target(File external, String group) { return group.equals("files") ? external : new File(external, group); }

    static void probeWritable(File external) throws IOException {
        File probe = null, committed = null;
        try {
            probe = File.createTempFile("phase5-probe-", ".tmp", external);
            committed = File.createTempFile("phase5-probe-", ".committed", external);
            byte[] bytes = ("MC4_PHASE5_PROBE_V1:" + probe.getName()).getBytes(StandardCharsets.UTF_8);
            // Do not use atomicWrite: this parent can deliberately be the verified private link.
            try (FileOutputStream stream = new FileOutputStream(probe)) {
                stream.write(bytes); stream.flush(); stream.getFD().sync();
            }
            if (!Arrays.equals(bytes, read(probe))) throw new IOException("Storage probe read-back failed: " + probe);
            rename(probe, committed); // Replace only the second unique file owned by this probe.
            if (!Arrays.equals(bytes, read(committed))) throw new IOException("Renamed storage probe read-back failed: " + committed);
        } finally {
            IOException cleanup = null;
            for (File owned : new File[]{probe, committed}) {
                if (owned != null && !owned.delete()) {
                    try { if (exists(owned)) cleanup = new IOException("Cannot remove owned storage probe: " + owned); }
                    catch (IOException e) { cleanup = e; }
                }
            }
            if (cleanup != null) throw cleanup;
        }
    }

    private static void probeLink(File data, File external) throws IOException {
        File probe = new File(data, ".phase5-link-probe");
        if (exists(probe)) verifyLink(probe, external); else symlink(external, probe);
        try {
            if (!sameDirectory(probe, external)) throw new IOException("Private probe alias has a different physical directory.");
            probeWritable(probe);
            if (!sameDirectory(probe, external)) throw new IOException("Private probe alias changed physical directory.");
        }
        finally { if (!probe.delete()) throw new IOException("Cannot remove link probe: " + probe); }
    }

    private static void verifyLink(File link, File target) throws IOException {
        try {
            // Read the link itself. File canonicalization may cache a pre-switch private path.
            if (!isLink(link) || !Os.readlink(link.getAbsolutePath()).equals(target.getAbsolutePath()) || !target.isDirectory())
                throw new IOException("Unexpected/missing data link: " + link + " -> " + target);
        } catch (ErrnoException e) { throw new IOException("Cannot read data link: " + link, e); }
    }

    private static boolean sameDirectory(File a, File b) throws IOException {
        try {
            StructStat left = Os.stat(a.getAbsolutePath()), right = Os.stat(b.getAbsolutePath());
            return OsConstants.S_ISDIR(left.st_mode) && OsConstants.S_ISDIR(right.st_mode)
                    && left.st_dev == right.st_dev && left.st_ino == right.st_ino;
        } catch (ErrnoException e) { throw new IOException("Cannot verify native alias/app directory.", e); }
    }

    private static void symlink(File target, File link) throws IOException {
        try { Os.symlink(target.getAbsolutePath(), link.getAbsolutePath()); }
        catch (ErrnoException e) { throw new IOException("App UID cannot create data link: " + link, e); }
        verifyLink(link, target);
    }

    private static StructStat stat(File file) throws IOException {
        try { return Os.lstat(file.getAbsolutePath()); }
        catch (ErrnoException e) {
            if (e.errno == OsConstants.ENOENT) return null;
            throw new IOException(e);
        }
    }

    private static boolean exists(File file) throws IOException { return stat(file) != null; }
    private static boolean isLink(File file) throws IOException { StructStat s = stat(file); return s != null && OsConstants.S_ISLNK(s.st_mode); }
    private static boolean isDirectory(File file) throws IOException {
        StructStat s = stat(file);
        if (s != null && OsConstants.S_ISLNK(s.st_mode)) throw new IOException("Unexpected symlink: " + file);
        return s != null && OsConstants.S_ISDIR(s.st_mode);
    }

    private static void directory(File file) throws IOException {
        if (!exists(file) && !file.mkdirs()) throw new IOException("Cannot create directory: " + file);
        if (!isDirectory(file)) throw new IOException("Not a real directory: " + file);
    }

    private static void regularOrAbsent(File file) throws IOException {
        StructStat s = stat(file);
        if (s != null && !OsConstants.S_ISREG(s.st_mode)) throw new IOException("Not a regular file: " + file);
    }

    private static File[] children(File file) throws IOException {
        if (!isDirectory(file)) throw new IOException("Not a real directory: " + file);
        File[] result = file.listFiles();
        if (result == null) throw new IOException("Cannot list directory: " + file);
        Arrays.sort(result, (a, b) -> a.getName().compareTo(b.getName()));
        return result;
    }

    private static boolean same(File a, File b) throws IOException {
        regularOrAbsent(a); regularOrAbsent(b);
        return exists(a) && exists(b) && a.length() == b.length() && fileHash(a).equals(fileHash(b));
    }

    static String fileHash(File file) throws IOException {
        regularOrAbsent(file);
        MessageDigest digest = sha256();
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192]; int count;
            while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format(java.util.Locale.ROOT, "%02x", value & 255));
        return text.toString();
    }

    private static byte[] read(File file) throws IOException {
        regularOrAbsent(file);
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[8192]; int count;
            while ((count = input.read(buffer)) != -1) result.write(buffer, 0, count);
        }
        return result.toByteArray();
    }

    private static void atomicCopy(File source, File destination) throws IOException {
        directory(destination.getParentFile());
        regularOrAbsent(destination);
        File temporary = File.createTempFile("phase5-copy-", ".tmp", destination.getParentFile());
        try {
            try (FileInputStream input = new FileInputStream(source); FileOutputStream output = new FileOutputStream(temporary)) {
                byte[] buffer = new byte[8192]; int count;
                while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count);
                output.flush(); output.getFD().sync();
            }
            if (!same(source, temporary)) throw new IOException("Copy hash mismatch: " + destination);
            if (exists(destination)) throw new IOException("Destination appeared during copy: " + destination);
            rename(temporary, destination);
            if (!same(source, destination)) throw new IOException("Committed hash mismatch: " + destination);
        } finally { if (temporary.exists()) temporary.delete(); }
    }

    static void atomicWrite(File destination, byte[] data) throws IOException {
        directory(destination.getParentFile());
        regularOrAbsent(destination);
        File temporary = File.createTempFile("phase5-write-", ".tmp", destination.getParentFile());
        try {
            try (FileOutputStream output = new FileOutputStream(temporary)) {
                output.write(data); output.flush(); output.getFD().sync();
            }
            if (!Arrays.equals(data, read(temporary))) throw new IOException("Write verification failed: " + destination);
            rename(temporary, destination);
            if (!Arrays.equals(data, read(destination))) throw new IOException("Commit verification failed: " + destination);
        } finally { if (temporary.exists()) temporary.delete(); }
    }

    private static void rename(File from, File to) throws IOException {
        try { Os.rename(from.getAbsolutePath(), to.getAbsolutePath()); }
        catch (ErrnoException e) { throw new IOException("Atomic rename failed: " + from + " -> " + to, e); }
    }

    public static synchronized boolean write(String path, String data) {
        return writeBytes(path, data.getBytes(StandardCharsets.UTF_8));
    }

    public static synchronized boolean writeBytes(String path, byte[] data) {
        try {
            requireReady();
            File destination = new File(path).getCanonicalFile();
            if (!destination.getPath().startsWith(root.getPath() + File.separator))
                throw new IOException("Persistent write is outside external game storage: " + path);
            atomicWrite(destination, data);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
