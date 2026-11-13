package com.gameloft.android.ANMP.GloftM4HM;

import android.content.Context;
import android.system.Os;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Host filesystem checks only. The runner supplies Os stubs backed by real NIO operations.
 * These checks do not certify Android UID/SELinux/FUSE, SQLite CRUD or SharedPreferences APIs.
 */
public final class AppDataHostCheck {
    private static Path scratch;
    private static int passed;

    public static void main(String[] args) throws Exception {
        scratch = Files.createTempDirectory(new File(args[0]).toPath(), "run-");
        snapshot(); partialSnapshot(); snapshotConflict(); saveGroupConflict(); repeatedMerge();
        atomicFailure(); writableProbe(); failedWritableProbe(); missingExternal();
        if (symlinksAvailable()) { completeCold(); interruptedSwitch(); corruptMarker(); corruptArchive(); }
        else System.out.println("SKIP: host symbolic links unavailable; Android link bootstrap needs device proof.");
        System.out.println("HOST_FILESYSTEM_PASS cases=" + passed + " scratch=" + scratch);
    }

    private static File dir(String name) throws IOException {
        return Files.createDirectories(scratch.resolve(name)).toFile();
    }
    private static void put(File parent, String name, String content) throws IOException {
        Path path = parent.toPath().resolve(name);
        Files.createDirectories(path.getParent());
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
    }
    private static String get(File parent, String name) throws IOException {
        return new String(Files.readAllBytes(parent.toPath().resolve(name)), StandardCharsets.UTF_8);
    }
    private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
    private static void ok(String name) { passed++; System.out.println("PASS " + name); }
    private static void fails(Throwing operation, String name) throws Exception {
        try { operation.run(); } catch (IOException expected) { return; }
        throw new AssertionError("Expected checked failure: " + name);
    }
    private interface Throwing { void run() throws Exception; }

    private static void snapshot() throws Exception {
        File source = dir("snapshot/source"), target = dir("snapshot/target");
        byte[] binary = new byte[256]; for (int i = 0; i < binary.length; i++) binary[i] = (byte)i;
        Files.write(new File(source, "SaveGame.bin").toPath(), binary);
        put(source, "nested/данные.txt", "UTF-8\n1234567890123456789\n");
        new File(source, "empty").mkdir();
        AppData.copySnapshot(source, target);
        check(AppData.treeHash(source).equals(AppData.treeHash(target)), "snapshot tree hash");
        check(Arrays.equals(binary, Files.readAllBytes(new File(target, "SaveGame.bin").toPath())), "binary bytes");
        check(new File(target, "empty").isDirectory(), "empty directory");
        ok("snapshot bytes, UTF-8, nested and empty directories");
    }
    private static void partialSnapshot() throws Exception {
        File source = dir("partial/source"), target = dir("partial/target");
        put(source, "a", "first"); put(source, "b", "second"); put(target, "a", "first");
        AppData.copySnapshot(source, target); AppData.copySnapshot(source, target);
        check(AppData.treeHash(source).equals(AppData.treeHash(target)), "partial recovery");
        ok("incomplete snapshot retry is idempotent");
    }
    private static void snapshotConflict() throws Exception {
        File source = dir("conflict/source"), target = dir("conflict/target");
        put(source, "save", "private"); put(target, "save", "archive-corrupt");
        fails(() -> AppData.copySnapshot(source, target), "snapshot conflict");
        check(get(source, "save").equals("private") && get(target, "save").equals("archive-corrupt"), "preserve both");
        ok("snapshot corruption fails while preserving both copies");
    }
    private static void saveGroupConflict() throws Exception {
        File source = dir("saves/source"), target = dir("saves/target");
        put(source, "SaveGame.bin", "private-save"); put(source, "CheckPoint.bin", "private-checkpoint");
        put(source, "backupSaveFile.dat", "private-backup"); put(source, "BI.trk", "tracking");
        put(target, "SaveGame.bin", "external-current");
        check(AppData.mergeFiles(source, target) == 3, "whole save group skipped");
        check(get(target, "SaveGame.bin").equals("external-current"), "external save preserved");
        check(!new File(target, "CheckPoint.bin").exists() && !new File(target, "backupSaveFile.dat").exists(), "no mixed generations");
        check(get(target, "BI.trk").equals("tracking"), "independent file copied");
        ok("save/checkpoint/backup conflict keeps external generation intact");
    }
    private static void repeatedMerge() throws Exception {
        File source = dir("retry/source"), target = dir("retry/target");
        put(source, "SaveGame.bin", "old"); put(source, "CheckPoint.bin", "checkpoint"); put(source, "backupSaveFile.dat", "backup");
        AppData.mergeFiles(source, target);
        put(target, "SaveGame.bin", "updated-after-gameplay");
        AppData.mergeFiles(source, target);
        check(get(target, "SaveGame.bin").equals("updated-after-gameplay"), "new external save overwritten");
        check(get(source, "SaveGame.bin").equals("old"), "private original changed");
        ok("retry after new gameplay preserves current external save");
    }
    private static void atomicFailure() throws Exception {
        File destination = new File(dir("atomic"), "config");
        AppData.atomicWrite(destination, "previous".getBytes(StandardCharsets.UTF_8));
        Os.failRenameAfter = 0;
        fails(() -> AppData.atomicWrite(destination, "replacement".getBytes(StandardCharsets.UTF_8)), "rename failure");
        check(get(destination.getParentFile(), "config").equals("previous"), "old data changed on failed rename");
        check(destination.getParentFile().listFiles().length == 1, "temporary file leaked");
        AppData.atomicWrite(destination, "replacement".getBytes(StandardCharsets.UTF_8));
        check(get(destination.getParentFile(), "config").equals("replacement"), "replacement missing");
        ok("failed atomic rename preserves previous file and closes/cleans temporary");
    }
    private static void missingExternal() throws Exception {
        final File data = dir("missing/data"); put(data, "files/SaveGame.bin", "retained");
        Context context = new Context() {
            @Override public File getDataDir() { return data; }
            @Override public File getExternalFilesDir(String type) { return null; }
            @Override public String getPackageName() { return "com.gameloft.android.ANMP.GloftM4HM"; }
        };
        fails(() -> AppData.initialize(context), "null external");
        check(get(data, "files/SaveGame.bin").equals("retained"), "private data changed");
        check(!new File(data, ".phase5-data.lock").exists(), "private mutation before external check");
        ok("null external root stops before any private migration mutation");
    }

    private static void writableProbe() throws Exception {
        File destination = dir("probe-success"); put(destination, "unrelated", "preserve");
        Os.lastRenamedFileSize = -1;
        AppData.probeWritable(destination);
        check(Os.lastRenamedFileSize > 0, "probe renamed an empty file");
        check(destination.listFiles().length == 1 && get(destination, "unrelated").equals("preserve"), "probe cleanup changed unrelated data");
        ok("nonempty write/read/sync/rename/read probe cleans only its unique files");
    }
    private static void failedWritableProbe() throws Exception {
        File destination = dir("probe-failure"); put(destination, "unrelated", "preserve");
        Os.failRenameAfter = 0;
        fails(() -> AppData.probeWritable(destination), "probe rename failure");
        check(destination.listFiles().length == 1 && get(destination, "unrelated").equals("preserve"), "failed probe left files or changed unrelated data");
        ok("failed probe rename stops and removes both owned temporary names");
    }

    private static boolean symlinksAvailable() throws Exception {
        Path target = dir("symbolic-link-target").toPath(), link = scratch.resolve("symbolic-link-probe");
        try { Files.createSymbolicLink(link, target); Files.delete(link); return true; }
        catch (IOException | UnsupportedOperationException unsupported) { return false; }
    }
    private static File[] fixture(String name) throws IOException {
        File data = dir(name + "/data"), external = dir(name + "/external");
        put(data, "files/SaveGame.bin", "native-save"); put(data, "files/CheckPoint.bin", "checkpoint");
        put(data, "files/backupSaveFile.dat", "backup"); put(data, "shared_prefs/MC4Prefs.xml", "prefs-long-and-utf8");
        put(data, "databases/gameloft_sharing", "database"); put(data, "databases/gameloft_sharing-wal", "wal");
        put(data, "databases/gameloft_sharing-shm", "shm"); put(data, "databases/gameloft_sharing-journal", "journal");
        return new File[]{data, external};
    }
    private static void completeCold() throws Exception {
        File[] f = fixture("complete"); AppData.prepare(f[0], f[1]);
        for (String group : new String[]{"files", "shared_prefs", "databases"}) {
            File target = group.equals("files") ? f[1] : new File(f[1], group);
            check(new File(f[0], group).getCanonicalFile().equals(target.getCanonicalFile()), "alias root " + group);
            check(new File(f[0], ".phase5-original-" + group).isDirectory(), "original not retained " + group);
        }
        put(f[0], "files/SaveGame.bin", "updated-via-private-alias");
        check(get(f[1], "SaveGame.bin").equals("updated-via-private-alias"), "new write is not external");
        AppData.prepare(f[0], f[1]); AppData.prepare(f[0], f[1]);
        check(get(f[1], "SaveGame.bin").equals("updated-via-private-alias"), "cold retry restored stale original");
        check(get(f[1], "databases/gameloft_sharing-wal").equals("wal") && get(f[1], "databases/gameloft_sharing-shm").equals("shm"), "sidecars lost");
        ok("bootstrap links, retained originals, sidecars, alias write and two cold retries");
    }
    private static void interruptedSwitch() throws Exception {
        File[] f = fixture("interrupted");
        // Two probe renames + three archive copies + three live copies + original rename;
        // interrupt the next rename, before the files link takes its live logical name.
        Os.failRenameAfter = 9;
        fails(() -> AppData.prepare(f[0], f[1]), "injected migration interruption");
        Os.failRenameAfter = -1;
        AppData.prepare(f[0], f[1]);
        check(get(f[1], "SaveGame.bin").equals("native-save"), "interrupted save migration");
        check(new File(f[0], "files").getCanonicalFile().equals(f[1].getCanonicalFile()), "recovery alias");
        ok("interrupted switch recovers without dropping original/source data");
    }
    private static void corruptMarker() throws Exception {
        File[] f = fixture("marker"); AppData.prepare(f[0], f[1]);
        put(f[1], "SaveGame.bin", "current"); put(f[1], ".phase5-data-links-v1", "corrupt");
        fails(() -> AppData.prepare(f[0], f[1]), "corrupt marker");
        check(get(f[1], "SaveGame.bin").equals("current"), "corrupt marker overwrote save");
        check(get(f[0], ".phase5-original-files/SaveGame.bin").equals("native-save"), "original lost");
        ok("corrupt completion marker blocks startup and retains current/original saves");
    }
    private static void corruptArchive() throws Exception {
        File[] f = fixture("archive"); AppData.prepare(f[0], f[1]);
        put(f[1], ".phase5-migration-archive/files/SaveGame.bin", "corrupt");
        fails(() -> AppData.prepare(f[0], f[1]), "corrupt archive");
        check(get(f[1], "SaveGame.bin").equals("native-save"), "active save modified");
        check(get(f[0], ".phase5-original-files/SaveGame.bin").equals("native-save"), "private original modified");
        ok("corrupt archived snapshot blocks startup without modifying game data");
    }
}
