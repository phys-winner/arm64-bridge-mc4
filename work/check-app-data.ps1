param(
    [string]$JdkBin = (Join-Path $env:JAVA_HOME 'bin'),
    [string]$AndroidJar = (Join-Path $env:ANDROID_SDK_ROOT 'platforms\android-32\android.jar')
)
$ErrorActionPreference = 'Stop'
$taskRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$taskOutput = Join-Path $taskRoot 'appdata-hostcheck'
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null
$taskSdkClasses = Join-Path $taskOutput 'sdk-classes'
New-Item -ItemType Directory -Path $taskSdkClasses -Force | Out-Null
& (Join-Path $JdkBin 'javac.exe') --release 8 -encoding UTF-8 -classpath $AndroidJar -d $taskSdkClasses (Join-Path $taskRoot 'AppData.java')
if ($LASTEXITCODE -ne 0) { throw 'Android SDK API compilation failed.' }
$taskStubs = @{
    'android/content/Context.java' = @'
package android.content;
import java.io.File;
public class Context {
    public File getDataDir() { throw new UnsupportedOperationException(); }
    public File getExternalFilesDir(String type) { throw new UnsupportedOperationException(); }
    public String getPackageName() { throw new UnsupportedOperationException(); }
}
'@
    'android/app/Application.java' = @'
package android.app;
import android.content.Context;
public class Application extends Context {
    protected void attachBaseContext(Context base) {}
    public interface ActivityLifecycleCallbacks {
        void onActivityCreated(Activity owner, android.os.Bundle state);
        void onActivityStarted(Activity owner);
        void onActivityResumed(Activity owner);
        void onActivityPaused(Activity owner);
        void onActivityStopped(Activity owner);
        void onActivitySaveInstanceState(Activity owner, android.os.Bundle state);
        void onActivityDestroyed(Activity owner);
    }
    public void registerActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) { throw new UnsupportedOperationException(); }
    public void unregisterActivityLifecycleCallbacks(ActivityLifecycleCallbacks callback) { throw new UnsupportedOperationException(); }
}
'@
    'android/system/ErrnoException.java' = @'
package android.system;
public class ErrnoException extends Exception {
    public final int errno;
    public ErrnoException(String name, int errno, Throwable cause) { super(name, cause); this.errno = errno; }
}
'@
    'android/system/StructStat.java' = @'
package android.system;
public class StructStat {
    public final int st_mode; public final long st_dev, st_ino;
    public StructStat(int mode, Object key) { st_mode = mode; st_dev = 1; st_ino = key == null ? 0 : key.hashCode(); }
}
'@
    'android/system/OsConstants.java' = @'
package android.system;
public final class OsConstants {
    public static final int ENOENT = 2;
    public static boolean S_ISREG(int mode) { return mode == 0x8000; }
    public static boolean S_ISDIR(int mode) { return mode == 0x4000; }
    public static boolean S_ISLNK(int mode) { return mode == 0xa000; }
}
'@
    'android/system/Os.java' = @'
package android.system;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
public final class Os {
    public static int failRenameAfter = -1;
    public static long lastRenamedFileSize = -1;
    public static StructStat lstat(String path) throws ErrnoException {
        try {
            BasicFileAttributes a = Files.readAttributes(Paths.get(path), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            return new StructStat(a.isSymbolicLink() ? 0xa000 : a.isDirectory() ? 0x4000 : a.isRegularFile() ? 0x8000 : 0, a.fileKey());
        } catch (NoSuchFileException e) { throw new ErrnoException("lstat", 2, e); }
        catch (IOException e) { throw new ErrnoException("lstat", 5, e); }
    }
    public static void symlink(String target, String link) throws ErrnoException {
        try { Files.createSymbolicLink(Paths.get(link), Paths.get(target)); }
        catch (IOException | UnsupportedOperationException e) { throw new ErrnoException("symlink", 13, e); }
    }
    public static String readlink(String link) throws ErrnoException {
        try { return Files.readSymbolicLink(Paths.get(link)).toString(); }
        catch (IOException e) { throw new ErrnoException("readlink", 5, e); }
    }
    public static StructStat stat(String path) throws ErrnoException {
        try { return lstat(Paths.get(path).toRealPath().toString()); }
        catch (IOException e) { throw new ErrnoException("stat", 5, e); }
    }
    public static void rename(String from, String to) throws ErrnoException {
        if (failRenameAfter >= 0 && failRenameAfter-- == 0) {
            failRenameAfter = -1; throw new ErrnoException("injected rename failure", 5, null);
        }
        try {
            lastRenamedFileSize = Files.size(Paths.get(from));
            Files.move(Paths.get(from), Paths.get(to), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        catch (IOException e) { throw new ErrnoException("rename", 5, e); }
    }
}
'@
    'android/util/Log.java' = @'
package android.util;
public class Log {
    public static int i(String tag, String text) { System.out.println(tag + ": " + text); return 0; }
    public static int w(String tag, String text) { System.out.println(tag + ": " + text); return 0; }
    public static int e(String tag, String text, Throwable e) { System.out.println(tag + ": " + text); return 0; }
}
'@
}
$taskSourcePaths = @()
foreach ($entry in $taskStubs.GetEnumerator()) {
    $taskPath = Join-Path $taskOutput ('stubs/' + $entry.Key)
    New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($taskPath)) -Force | Out-Null
    [System.IO.File]::WriteAllText($taskPath, $entry.Value, [System.Text.UTF8Encoding]::new($false))
    $taskSourcePaths += $taskPath
}
$taskHostClasses = Join-Path $taskOutput 'host-classes'
New-Item -ItemType Directory -Path $taskHostClasses -Force | Out-Null
$taskWebViewSource = Join-Path $taskOutput 'AppDataWebViewHostCheck.java'
$taskWebViewCheck = @'
package com.gameloft.android.ANMP.GloftM4HM;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Real host files/renames/links. Not an Android WebView, UID, SELinux or FUSE test. */
public final class AppDataWebViewHostCheck {
    private static final String PROFILE = "app_webview", MARKER = ".phase5-webview-links-v1";
    private static Path scratch;
    private static int passed;
    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory(new File(args[0]).toPath(), "webview-");
        insidePrivate(); conflictingPrivate(); conflictingArchive(); invalidMarkers();
        if (symlinksAvailable()) {
            completeAndV1Compatible(); externalProfileWins(); interruptedStage();
            interruptedLink(false); interruptedLink(true); externalOnlyMarker();
            corruptCompletion(false); corruptCompletion(true); missingExternalMarker();
        } else {
            deniedLink();
            System.out.println("SKIP WEBVIEW_LINK_CASES: host symbolic links unavailable; completed/recovery bootstrap needs Android proof.");
        }
        System.out.println("WEBVIEW_HOST_FILESYSTEM_PASS cases=" + passed + " scratch=" + scratch);
    }
    private static File dir(String name) throws IOException {
        return Files.createDirectories(scratch.resolve(name)).toFile();
    }
    private static void put(File parent, String name, String value) throws IOException {
        Path path = parent.toPath().resolve(name);
        Files.createDirectories(path.getParent());
        Files.write(path, value.getBytes(StandardCharsets.UTF_8));
    }
    private static String get(File parent, String name) throws IOException {
        return new String(Files.readAllBytes(parent.toPath().resolve(name)), StandardCharsets.UTF_8);
    }
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
    private static void ok(String name) { passed++; System.out.println("PASS WEBVIEW " + name); }
    private static void fails(File data, File external) throws Exception {
        try { AppData.prepareWebView(data, external); }
        catch (IOException expected) { return; }
        throw new AssertionError("Expected checked WebView bootstrap failure.");
    }
    private static File profile(File data) { return new File(data, PROFILE); }
    private static File original(File data) { return new File(data, ".phase5-original-" + PROFILE); }
    private static File archive(File external) { return new File(external, ".phase5-migration-archive/" + PROFILE); }
    private static File[] fixture(String name) throws IOException {
        File data = dir(name + "/data"), external = dir(name + "/external");
        put(data, PROFILE + "/pref_store", "private prefs UTF-8: \u4fdd\u5b58");
        put(data, PROFILE + "/Default/Local Storage/leveldb/CURRENT", "MANIFEST-000001\n");
        put(data, PROFILE + "/Default/Local Storage/leveldb/MANIFEST-000001", "private manifest");
        put(data, PROFILE + "/Default/Local Storage/leveldb/000002.log", "private durable entries");
        return new File[]{data, external};
    }
    private static boolean symlinksAvailable() throws IOException {
        Path target = dir("link-target").toPath(), link = scratch.resolve("link-probe");
        try { Files.createSymbolicLink(link, target); Files.delete(link); return true; }
        catch (IOException | UnsupportedOperationException unsupported) { return false; }
    }
    private static void preserved(File[] f, String expected) throws Exception {
        check(AppData.treeHash(profile(f[0])).equals(expected), "private profile changed after refusal");
        check(!new File(f[0], MARKER).exists(), "private completion marker appeared on refusal");
    }
    private static void insidePrivate() throws Exception {
        File[] f = fixture("inside"); String hash = AppData.treeHash(profile(f[0]));
        File external = new File(f[0], "wrong-external");
        fails(f[0], external); preserved(f, hash);
        check(!external.exists(), "created invalid external root");
        ok("external root inside private storage refuses before mutation");
    }
    private static void conflictingPrivate() throws Exception {
        File[] f = fixture("private-conflict"); String hash = AppData.treeHash(profile(f[0]));
        put(original(f[0]), "pref_store", "retained other generation");
        String retained = AppData.treeHash(original(f[0]));
        fails(f[0], f[1]); preserved(f, hash);
        check(AppData.treeHash(original(f[0])).equals(retained), "retained profile overwritten");
        ok("ambiguous private live/original generations are both preserved");
    }
    private static void conflictingArchive() throws Exception {
        File[] f = fixture("archive-conflict"); String hash = AppData.treeHash(profile(f[0]));
        AppData.copySnapshot(profile(f[0]), archive(f[1]));
        put(archive(f[1]), "pref_store", "corrupt preexisting archive");
        String archived = AppData.treeHash(archive(f[1]));
        fails(f[0], f[1]); preserved(f, hash);
        check(AppData.treeHash(archive(f[1])).equals(archived), "conflicting archive overwritten");
        ok("conflicting archive blocks bootstrap without overwriting either profile");
    }
    private static void invalidMarkers() throws Exception {
        File[] f = fixture("invalid-marker"); String hash = AppData.treeHash(profile(f[0]));
        put(f[0], MARKER, "invalid"); put(f[1], MARKER, "invalid");
        fails(f[0], f[1]);
        check(AppData.treeHash(profile(f[0])).equals(hash), "invalid marker changed private profile");
        check(get(f[0], MARKER).equals("invalid") && get(f[1], MARKER).equals("invalid"), "invalid markers repaired silently");
        put(f[1], MARKER, "different"); fails(f[0], f[1]);
        check(get(f[1], MARKER).equals("different"), "mismatched marker repaired silently");
        ok("invalid or mismatched marker pair refuses without fallback");
    }
    private static void deniedLink() throws Exception {
        File[] f = fixture("denied-link"); String hash = AppData.treeHash(profile(f[0]));
        try { AppData.prepareWebView(f[0], f[1]); throw new AssertionError("Expected unavailable host symlink."); }
        catch (IOException expected) {
            check(expected.getMessage().startsWith("App UID cannot create data link:"), "unrelated failure instead of denied link: " + expected);
        }
        preserved(f, hash);
        check(AppData.treeHash(archive(f[1])).equals(hash), "archive not retained after link denial");
        check(AppData.treeHash(profile(f[1])).equals(hash), "staged profile not retained after link denial");
        check(!original(f[0]).exists() && !new File(f[1], MARKER).exists(), "marked unavailable link completed");
        ok("denied host link leaves private source plus verified external copies and no completion marker");
    }
    private static void completeAndV1Compatible() throws Exception {
        File[] f = fixture("complete"); String hash = AppData.treeHash(profile(f[0]));
        put(f[0], "files/SaveGame.bin", "game save");
        put(f[0], "shared_prefs/game.xml", "game prefs"); put(f[0], "databases/game.db", "game db");
        AppData.prepare(f[0], f[1]);
        File v1Private = new File(f[0], ".phase5-data-links-v1"), v1External = new File(f[1], ".phase5-data-links-v1");
        byte[] privateBytes = Files.readAllBytes(v1Private.toPath()), externalBytes = Files.readAllBytes(v1External.toPath());
        AppData.prepareWebView(f[0], f[1]);
        check(profile(f[0]).getCanonicalFile().equals(profile(f[1]).getCanonicalFile()), "WebView alias");
        check(AppData.treeHash(original(f[0])).equals(hash) && AppData.treeHash(archive(f[1])).equals(hash), "original/archive hashes");
        put(f[0], PROFILE + "/pref_store", "live prefs after first launch");
        put(f[0], PROFILE + "/Default/Local Storage/leveldb/000002.log", "live updated entries");
        AppData.prepareWebView(f[0], f[1]); AppData.prepareWebView(f[0], f[1]); AppData.prepare(f[0], f[1]);
        check(get(profile(f[1]), "pref_store").equals("live prefs after first launch"), "retry restored stale profile");
        check(AppData.treeHash(archive(f[1])).equals(hash), "live change modified archive");
        check(Arrays.equals(privateBytes, Files.readAllBytes(v1Private.toPath())) && Arrays.equals(externalBytes, Files.readAllBytes(v1External.toPath())), "V1 markers changed");
        ok("V1 remains byte-identical; WebView alias writes and two retries preserve live updates and immutable archive");
    }
    private static void externalProfileWins() throws Exception {
        File[] f = fixture("external-wins"); String hash = AppData.treeHash(profile(f[0]));
        put(profile(f[1]), "Default/Local Storage/leveldb/CURRENT", "EXTERNAL-MANIFEST\n");
        String externalHash = AppData.treeHash(profile(f[1]));
        AppData.prepareWebView(f[0], f[1]);
        check(AppData.treeHash(profile(f[1])).equals(externalHash), "mixed/overwrote external profile");
        check(!new File(profile(f[1]), "pref_store").exists(), "private prefs merged into external generation");
        check(AppData.treeHash(original(f[0])).equals(hash) && AppData.treeHash(archive(f[1])).equals(hash), "private conflict not retained");
        ok("nonempty external profile wins whole; conflicting private generation remains archived");
    }
    private static void interruptedStage() throws Exception {
        File[] f = fixture("stage");
        put(archive(f[1]), "pref_store", get(profile(f[0]), "pref_store"));
        put(new File(f[1], ".phase5-stage-" + PROFILE), "Default/Local Storage/leveldb/CURRENT", "MANIFEST-000001\n");
        AppData.prepareWebView(f[0], f[1]);
        check(AppData.treeHash(original(f[0])).equals(AppData.treeHash(profile(f[1]))), "partial stage did not recover");
        ok("consistent partial archive/stage recover by hash-checked retry");
    }
    private static void interruptedLink(boolean activated) throws Exception {
        File[] f = fixture("link-" + activated);
        AppData.copySnapshot(profile(f[0]), profile(f[1]));
        Files.move(profile(f[0]).toPath(), original(f[0]).toPath());
        File link = activated ? profile(f[0]) : new File(f[0], ".phase5-link-" + PROFILE);
        Files.createSymbolicLink(link.toPath(), profile(f[1]).toPath());
        AppData.prepareWebView(f[0], f[1]);
        check(profile(f[0]).getCanonicalFile().equals(profile(f[1]).getCanonicalFile()), "interrupted alias recovery");
        check(AppData.treeHash(original(f[0])).equals(AppData.treeHash(archive(f[1]))), "recovery original/archive mismatch");
        ok("manual interrupted " + (activated ? "active" : "staged") + " link recovers without synthetic Os failures");
    }
    private static void externalOnlyMarker() throws Exception {
        File[] f = fixture("external-marker"); AppData.prepareWebView(f[0], f[1]);
        check(new File(f[0], MARKER).delete(), "remove only owned private marker");
        put(profile(f[1]), "pref_store", "current after migration");
        AppData.prepareWebView(f[0], f[1]);
        check(get(profile(f[1]), "pref_store").equals("current after migration"), "recovery overwrote current profile");
        check(Arrays.equals(Files.readAllBytes(new File(f[0], MARKER).toPath()), Files.readAllBytes(new File(f[1], MARKER).toPath())), "marker pair not recovered");
        ok("external-only completion recovers private marker without reverting live data");
    }
    private static void corruptCompletion(boolean archived) throws Exception {
        File[] f = fixture("corrupt-" + archived); AppData.prepareWebView(f[0], f[1]);
        String live = AppData.treeHash(profile(f[1])), retained = AppData.treeHash(original(f[0]));
        if (archived) put(archive(f[1]), "pref_store", "corrupt archive"); else put(f[1], MARKER, "corrupt marker");
        fails(f[0], f[1]);
        check(AppData.treeHash(profile(f[1])).equals(live) && AppData.treeHash(original(f[0])).equals(retained), "corruption refusal changed data");
        ok("corrupt " + (archived ? "archive" : "marker") + " refuses without private fallback");
    }
    private static void missingExternalMarker() throws Exception {
        File[] f = fixture("missing-marker"); AppData.prepareWebView(f[0], f[1]);
        String live = AppData.treeHash(profile(f[1])); check(new File(f[1], MARKER).delete(), "owned marker deletion");
        fails(f[0], f[1]);
        check(AppData.treeHash(profile(f[1])).equals(live) && !new File(f[1], MARKER).exists(), "lost external marker silently repaired");
        ok("missing external completion marker blocks startup and preserves live profile");
    }
}
'@
[System.IO.File]::WriteAllText($taskWebViewSource, $taskWebViewCheck, [System.Text.UTF8Encoding]::new($false))
& (Join-Path $JdkBin 'javac.exe') --release 8 -encoding UTF-8 -classpath $AndroidJar -d $taskHostClasses @taskSourcePaths (Join-Path $taskRoot 'AppData.java') (Join-Path $taskRoot 'AppDataHostCheck.java') $taskWebViewSource
if ($LASTEXITCODE -ne 0) { throw 'Host fixture compilation failed.' }
& (Join-Path $JdkBin 'java.exe') -classpath ($taskHostClasses + ';' + $AndroidJar) com.gameloft.android.ANMP.GloftM4HM.AppDataHostCheck $taskOutput
if ($LASTEXITCODE -ne 0) { throw 'Host filesystem self-check failed.' }
& (Join-Path $JdkBin 'java.exe') -classpath ($taskHostClasses + ';' + $AndroidJar) com.gameloft.android.ANMP.GloftM4HM.AppDataWebViewHostCheck $taskOutput
if ($LASTEXITCODE -ne 0) { throw 'WebView profile filesystem self-check failed.' }
Write-Output ('ANDROID_SDK_API_COMPILE_PASS android.jar=' + $AndroidJar)
