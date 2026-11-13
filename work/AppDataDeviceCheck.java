package com.gameloft.android.ANMP.GloftM4HM;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import android.util.Log;
import android.util.Xml;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.xmlpull.v1.XmlPullParser;
import org.json.JSONObject;
import org.json.JSONTokener;

/** Temporary diagnostic instrumentation only. Never include in the shipping APK.
 * File fixtures stay under unique private/external roots. Framework prefs and SQLite use
 * exact own UUID namespaces in the real app context, then delete only those namespaces.
 */
public final class AppDataDeviceCheck extends Instrumentation {
    private static final String TAG = "MC4DataCheck";
    private static final long LARGE = 9007199254740993L;
    private static final String TEXT = "Сохранение — 日本語 — Ω";
    private static final String WEBVIEW_KEY_PREFIX = ".phase5-webview-check-";
    private static final String WEBVIEW_ORIGIN = "https://mc4-phase5-check.invalid";
    private static final long WEBVIEW_GRACE_MILLIS = 10000;
    private static final String[] GROUPS = {"files", "shared_prefs", "databases"};
    private final Bundle result = new Bundle();
    private Context context;
    private File dataRoot, externalRoot, privateFixtures, externalFixtures;
    private String prefix, prefsName, databaseName;
    private String mode;
    private String webviewKey;
    private WebView diagnosticWebView;
    private boolean prefsOpened, databaseOpened;
    private int passed, failed;

    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        result.putString("requestedSerial", arguments == null ? "" : arguments.getString("authorized_serial", ""));
        mode = arguments == null ? "storage" : arguments.getString("mode", "storage");
        webviewKey = arguments == null ? null : arguments.getString("webview_key");
        result.putString("mode", mode);
        start();
    }

    @Override public void onStart() {
        try {
            context = getTargetContext();
            int uid = Process.myUid();
            result.putInt("actualProcessUID", uid);
            result.putInt("targetAppUID", context.getApplicationInfo().uid);
            result.putInt("actualProcessPID", Process.myPid());
            result.putBoolean("process64Bit", Process.is64Bit());
            result.putInt("sdk", Build.VERSION.SDK_INT);
            result.putString("model", Build.MODEL);
            check(uid == context.getApplicationInfo().uid && uid >= 10000 && uid != 2000, "Process is not target ordinary app UID.");
            check("5hgunfpbyldyvkgi".equals(result.getString("requestedSerial")), "Missing/wrong authorized_serial argument.");
            result.putBoolean("appDataReady", AppData.ready());
            result.putString("appDataError", AppData.error());
            if ("unavailable".equals(mode)) { unavailable(); return; }
            if (webviewMode()) { webview(); passed++; result.putString(mode, "PASS"); return; }
            boolean webviewFixtures = "webview-fixtures".equals(mode);
            check("storage".equals(mode) || webviewFixtures, "Unknown diagnostic mode.");
            if (webviewFixtures) check(context.getApplicationContext() instanceof AppData && AppData.ready(), "WebView fixtures require the real ready AppData Application.");
            dataRoot = context.getDataDir().getCanonicalFile();
            File external = context.getExternalFilesDir(null);
            check(external != null, "External root unavailable.");
            externalRoot = external.getCanonicalFile();
            result.putString("actualPrivateRoot", dataRoot.getPath());
            result.putString("actualExternalRoot", externalRoot.getPath());
            prefix = ".phase5-check-" + UUID.randomUUID().toString();
            prefsName = prefix + ".prefs";
            databaseName = prefix + ".db";
            privateFixtures = new File(dataRoot, prefix);
            externalFixtures = new File(externalRoot, prefix);
            check(!privateFixtures.exists() && !externalFixtures.exists(), "UUID fixture collision.");
            mkdir(privateFixtures); mkdir(externalFixtures);
            result.putString("fixturePrivate", privateFixtures.getPath());
            result.putString("fixtureExternal", externalFixtures.getPath());
            if (webviewFixtures) { webviewFixtures(); return; }
            for (String name : new String[]{"links_two_retries", "corrupt_marker", "corrupt_archive",
                    "interrupted_retained", "interrupted_active", "preferences", "sqlite"}) {
                try {
                    switch (name) {
                        case "links_two_retries": linksAndRetries(); break;
                        case "corrupt_marker": corruption(false); break;
                        case "corrupt_archive": corruption(true); break;
                        case "interrupted_retained": interrupted(false); break;
                        case "interrupted_active": interrupted(true); break;
                        case "preferences": preferences(); break;
                        case "sqlite": sqlite(); break;
                        default: throw new AssertionError(name);
                    }
                    passed++; result.putString(name, "PASS"); Log.i(TAG, name + " PASS");
                } catch (Throwable error) {
                    failed++; result.putString(name, "FAIL: " + error);
                    result.putString(name + ".trace", Log.getStackTraceString(error));
                    Log.e(TAG, name + " FAIL", error);
                }
            }
        } catch (Throwable error) {
            failed++; result.putString("startup", "FAIL: " + error);
            result.putString("startup.trace", Log.getStackTraceString(error));
            Log.e(TAG, "startup FAIL", error);
        } finally {
            try {
                if (webviewMode()) destroyDiagnosticWebView();
                else { cleanup(); result.putString("cleanup", "unavailable".equals(mode) ? "PASS: no file fixtures created" : "PASS: exact owned artifacts removed"); }
            }
            catch (Throwable error) { failed++; result.putString("cleanup", "FAIL: " + error); Log.e(TAG, "cleanup FAIL", error); }
            result.putInt("passed", passed); result.putInt("failed", failed);
            result.putString("status", failed == 0 ? "PASS" : "FAIL");
            result.putString("stream", "MC4 ordinary-UID data check: " + (failed == 0 ? "PASS" : "FAIL")
                    + "; uid=" + Process.myUid() + "; passed=" + passed + "; failed=" + failed + "\n");
            finish(failed == 0 ? Activity.RESULT_OK : Activity.RESULT_CANCELED, result);
        }
    }

    /** Exercise the real profile migration helper only in existing own-UUID fixture roots. */
    private void webviewFixtures() throws Exception {
        File actualProfile = new File(externalRoot, "app_webview");
        String actualHash = AppData.treeHash(actualProfile);
        check(!read(new File("/proc/self/maps")).contains("libModernCombat4.so"), "Native game library loaded before WebView fixtures.");
        for (String name : new String[]{"webview_two_retries", "webview_corrupt_marker", "webview_corrupt_archive", "webview_interrupted_marker_commit"}) {
            Bundle progress = new Bundle(); progress.putString("case", name); progress.putString("state", "RUNNING"); sendStatus(0, progress);
            try {
                switch (name) {
                    case "webview_two_retries": webviewRetries(); break;
                    case "webview_corrupt_marker": webviewCorruption(false); break;
                    case "webview_corrupt_archive": webviewCorruption(true); break;
                    case "webview_interrupted_marker_commit": webviewInterruptedCommit(); break;
                    default: throw new AssertionError(name);
                }
                passed++; result.putString(name, "PASS"); Log.i(TAG, name + " PASS");
            } catch (Throwable error) {
                failed++; result.putString(name, "FAIL: " + error); result.putString(name + ".trace", Log.getStackTraceString(error)); Log.e(TAG, name + " FAIL", error);
            }
            progress.putString("state", result.getString(name)); sendStatus(0, progress);
        }
        check(actualHash.equals(AppData.treeHash(actualProfile)), "WebView fixtures changed actual main profile.");
        check(AppData.ready() && !read(new File("/proc/self/maps")).contains("libModernCombat4.so"), "WebView fixtures changed readiness or loaded native game.");
        result.putString("webview_fixtures.main_profile_sha256", actualHash);
        result.putString("webview_fixtures.main_profile_unchanged", "PASS");
    }

    private File[] webviewFixture(String name) throws Exception {
        File[] f = fixture(name);
        put(new File(f[0], "app_webview/Default/Local Storage/profile-fixture.bin"), TEXT + " | original DOM profile fixture");
        put(new File(f[0], "app_webview/.profile-fixture"), "whole-profile root fixture");
        mkdir(new File(f[0], "app_webview/Default/empty-fixture"));
        return f;
    }

    private void webviewRetries() throws Exception {
        File[] f = webviewFixture("webview-retries");
        String sourceHash = AppData.treeHash(new File(f[0], "app_webview"));
        AppData.prepareWebView(f[0], f[1]); verifyWebviewLink(f);
        File original = new File(f[0], ".phase5-original-app_webview"), archive = new File(f[1], ".phase5-migration-archive/app_webview");
        File target = new File(f[1], "app_webview");
        check(sourceHash.equals(AppData.treeHash(target)) && sourceHash.equals(AppData.treeHash(original)) && sourceHash.equals(AppData.treeHash(archive)), "Whole WebView profile copy differs from source.");
        String markerHash = AppData.fileHash(new File(f[0], ".phase5-webview-links-v1"));
        put(new File(f[0], "app_webview/Default/Local Storage/profile-fixture.bin"), TEXT + " | updated external DOM profile fixture");
        String liveHash = AppData.treeHash(target);
        for (int i = 0; i < 2; i++) {
            AppData.prepareWebView(f[0], f[1]); verifyWebviewLink(f);
            check(liveHash.equals(AppData.treeHash(target)), "WebView retry replaced current live profile.");
            check(sourceHash.equals(AppData.treeHash(original)) && sourceHash.equals(AppData.treeHash(archive)), "WebView retry changed original/archive.");
            check(markerHash.equals(AppData.fileHash(new File(f[0], ".phase5-webview-links-v1")))
                    && markerHash.equals(AppData.fileHash(new File(f[1], ".phase5-webview-links-v1"))), "WebView retry rewrote marker pair.");
        }
        result.putString("webview_two_retries.live_sha256", liveHash); result.putString("webview_two_retries.original_archive_sha256", sourceHash);
    }

    private void webviewCorruption(boolean archiveCorruption) throws Exception {
        File[] f = webviewFixture(archiveCorruption ? "webview-archive" : "webview-marker");
        AppData.prepareWebView(f[0], f[1]); verifyWebviewLink(f);
        File target = new File(f[1], "app_webview"), original = new File(f[0], ".phase5-original-app_webview"), archive = new File(f[1], ".phase5-migration-archive/app_webview");
        String liveHash = AppData.treeHash(target), originalHash = AppData.treeHash(original);
        String privateMarkerHash = AppData.fileHash(new File(f[0], ".phase5-webview-links-v1"));
        File damaged = new File(f[1], archiveCorruption ? ".phase5-migration-archive/app_webview/Default/Local Storage/profile-fixture.bin" : ".phase5-webview-links-v1");
        AppData.atomicWrite(damaged, "deliberate-own-WebView-fixture-corruption".getBytes(StandardCharsets.UTF_8));
        String archiveHash = AppData.treeHash(archive), externalMarkerHash = AppData.fileHash(new File(f[1], ".phase5-webview-links-v1"));
        boolean rejected = false;
        try { AppData.prepareWebView(f[0], f[1]); }
        catch (IOException error) {
            String expected = archiveCorruption ? "archive" : "marker";
            check(error.getMessage() != null && error.getMessage().toLowerCase(Locale.ROOT).contains(expected), "Unrelated WebView corruption rejection: " + error);
            result.putString("webview_corrupt_" + expected + ".expectedFailure", error.toString()); rejected = true;
        }
        check(rejected, "Corrupt WebView fixture accepted."); verifyWebviewLink(f);
        check(liveHash.equals(AppData.treeHash(target)) && originalHash.equals(AppData.treeHash(original)), "WebView corruption rejection changed live/original profile.");
        check(archiveHash.equals(AppData.treeHash(archive)) && privateMarkerHash.equals(AppData.fileHash(new File(f[0], ".phase5-webview-links-v1")))
                && externalMarkerHash.equals(AppData.fileHash(new File(f[1], ".phase5-webview-links-v1"))), "WebView corruption rejection rewrote archive/markers.");
    }

    private void webviewInterruptedCommit() throws Exception {
        File[] f = webviewFixture("webview-interrupted-commit");
        AppData.prepareWebView(f[0], f[1]); verifyWebviewLink(f);
        File target = new File(f[1], "app_webview"), original = new File(f[0], ".phase5-original-app_webview"), archive = new File(f[1], ".phase5-migration-archive/app_webview");
        String originalHash = AppData.treeHash(original), archiveHash = AppData.treeHash(archive);
        String externalMarkerHash = AppData.fileHash(new File(f[1], ".phase5-webview-links-v1"));
        put(new File(f[0], "app_webview/Default/Local Storage/profile-fixture.bin"), TEXT + " | update before private-marker recovery");
        String liveHash = AppData.treeHash(target);
        File privateMarker = new File(f[0], ".phase5-webview-links-v1");
        check(privateMarker.getParentFile().getCanonicalFile().equals(f[0].getCanonicalFile())
                && OsConstants.S_ISREG(Os.lstat(privateMarker.getPath()).st_mode), "Unsafe owned WebView private marker recovery fixture.");
        check(privateMarker.delete(), "Cannot simulate own private-marker commit interruption.");
        AppData.prepareWebView(f[0], f[1]); verifyWebviewLink(f);
        check(externalMarkerHash.equals(AppData.fileHash(privateMarker))
                && externalMarkerHash.equals(AppData.fileHash(new File(f[1], ".phase5-webview-links-v1"))), "WebView interrupted commit did not restore exact marker bytes.");
        check(liveHash.equals(AppData.treeHash(target)) && originalHash.equals(AppData.treeHash(original))
                && archiveHash.equals(AppData.treeHash(archive)), "WebView interrupted marker recovery changed profile generations.");
    }

    private static void verifyWebviewLink(File[] f) throws Exception {
        File logical = new File(f[0], "app_webview"), physical = new File(f[1], "app_webview");
        check(OsConstants.S_ISLNK(Os.lstat(logical.getPath()).st_mode) && Os.readlink(logical.getPath()).equals(physical.getCanonicalPath()), "WebView fixture alias is not the exact external symlink.");
        sameFile(logical, physical);
    }

    private boolean webviewMode() {
        return "webview-write".equals(mode) || "webview-read".equals(mode) || "webview-cleanup".equals(mode);
    }

    /** Public Android APIs have no DOM-storage flush callback. Only a different-PID read proves persistence. */
    private void webview() throws Exception {
        check(context.getApplicationContext() instanceof AppData && AppData.ready(), "WebView requires the real ready AppData Application.");
        check(webviewKey != null && webviewKey.startsWith(WEBVIEW_KEY_PREFIX), "Missing/wrong webview_key prefix.");
        String suffix = webviewKey.substring(WEBVIEW_KEY_PREFIX.length());
        check(suffix.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                && UUID.fromString(suffix).toString().equals(suffix), "webview_key must contain one canonical lowercase UUID.");
        result.putString("webviewKey", webviewKey);
        result.putString("webviewOrigin", WEBVIEW_ORIGIN);
        result.putString("webviewProviderFlush", "UNSUPPORTED: public Android API has no DOM-storage flush callback");
        check(!read(new File("/proc/self/maps")).contains("libModernCombat4.so"), "Native game library already loaded before WebView check.");
        dataRoot = context.getDataDir().getCanonicalFile();
        File external = context.getExternalFilesDir(null);
        check(external != null, "External WebView root unavailable.");
        externalRoot = external.getCanonicalFile();
        check(new File(AppData.externalFolder()).getCanonicalFile().equals(externalRoot), "AppData external root differs from actual app context.");
        File logical = new File(dataRoot, "app_webview"), physical = new File(externalRoot, "app_webview");
        check(OsConstants.S_ISLNK(Os.lstat(logical.getPath()).st_mode), "WebView profile alias missing; refuse private fallback.");
        check(OsConstants.S_ISDIR(Os.lstat(physical.getPath()).st_mode), "External WebView profile is not a real directory.");
        sameFile(logical, physical);
        File profile = context.getDir("webview", Context.MODE_PRIVATE);
        sameFile(profile, physical);
        check(profile.getCanonicalFile().equals(physical.getCanonicalFile()), "Framework WebView profile resolved outside external profile.");
        StructStat stat = Os.stat(profile.getPath());
        result.putString("webviewProfileLogical", profile.getPath());
        result.putString("webviewProfileCanonical", profile.getCanonicalPath());
        result.putString("webviewProfileExternal", physical.getCanonicalPath());
        result.putLong("webviewProfileDevice", stat.st_dev); result.putLong("webviewProfileInode", stat.st_ino);
        final long deadline = SystemClock.elapsedRealtime() + 25000;
        CompletableFuture<Void> loaded = new CompletableFuture<>();
        bounded(new FutureTask<Void>(() -> {
            checkMainThread();
            diagnosticWebView = new WebView(context);
            diagnosticWebView.getSettings().setJavaScriptEnabled(true);
            diagnosticWebView.getSettings().setDomStorageEnabled(true);
            diagnosticWebView.getSettings().setBlockNetworkLoads(true);
            diagnosticWebView.getSettings().setAllowFileAccess(false);
            diagnosticWebView.getSettings().setAllowContentAccess(false);
            PackageInfo provider = WebView.getCurrentWebViewPackage();
            check(provider != null, "No current WebView provider package.");
            result.putString("webviewProvider", provider.packageName + "@" + provider.versionName + " (" + provider.versionCode + ")");
            diagnosticWebView.setWebViewClient(new WebViewClient() {
                @Override public void onPageFinished(WebView view, String url) {
                    try { checkMainThread(); check((WEBVIEW_ORIGIN + "/").equals(url), "Unexpected WebView page: " + url); loaded.complete(null); }
                    catch (Throwable error) { loaded.completeExceptionally(error); }
                }
            });
            diagnosticWebView.loadDataWithBaseURL(WEBVIEW_ORIGIN + "/", "<!doctype html><meta charset=\"utf-8\"><title>MC4 DOM storage check</title>", "text/html", "UTF-8", null);
            return null;
        }), true, webviewRemaining(deadline));
        webviewAwait(loaded, deadline);
        String key = JSONObject.quote(webviewKey);
        if ("webview-write".equals(mode)) {
            String initial = webviewValuePrefix("initial") + Process.myPid();
            String updated = webviewValuePrefix("updated") + Process.myPid();
            JSONObject first = webviewEvaluate("if(localStorage.getItem(k)!==null)throw new Error('UUID key already exists');localStorage.setItem(k," + JSONObject.quote(initial) + ");", key, deadline);
            check(initial.equals(first.getString("value")), "Initial DOM storage read differs from write.");
            JSONObject second = webviewEvaluate("if(localStorage.getItem(k)!==" + JSONObject.quote(initial) + ")throw new Error('Initial value changed');localStorage.setItem(k," + JSONObject.quote(updated) + ");", key, deadline);
            check(updated.equals(second.getString("value")), "Updated DOM storage read differs from write.");
            result.putString("webviewInitialValue", initial); result.putString("webviewValue", updated);
            result.putInt("webviewWriterPID", Process.myPid());
            result.putString("webviewDurability", "PENDING: destroy then separate-process webview-read required");
            webviewGrace(deadline);
        } else if ("webview-read".equals(mode)) {
            JSONObject stored = webviewEvaluate("", key, deadline);
            result.putString("webviewObservedState", stored.toString());
            result.putBoolean("webviewObservedValueIsNull", stored.isNull("value"));
            String value = stored.isNull("value") ? "null" : stored.getString("value"), prefix = webviewValuePrefix("updated");
            result.putString("webviewObservedValue", value);
            check(value.startsWith(prefix) && value.substring(prefix.length()).matches("[1-9][0-9]{0,9}"), "Cold DOM value is absent, initial, or unrelated.");
            int writerPID = Integer.parseInt(value.substring(prefix.length()));
            check(writerPID != Process.myPid(), "Cold DOM read reused writer process.");
            result.putString("webviewValue", value); result.putInt("webviewWriterPID", writerPID);
            result.putString("webviewDurability", "PASS: updated value read by different process PID");
        } else {
            JSONObject removed = webviewEvaluate("var before=localStorage.getItem(k);localStorage.removeItem(k);", key, deadline);
            check(removed.isNull("value"), "Exact own DOM key still present after cleanup.");
            result.putString("webviewValueBeforeCleanup", removed.isNull("before") ? "null" : removed.getString("before"));
            result.putString("webviewValue", "null");
            result.putString("webviewDurability", "PENDING: cleanup persistence is asynchronous; repeat cleanup in a cold process to observe absence");
            webviewGrace(deadline);
        }
        check(AppData.ready(), "WebView check changed bootstrap readiness.");
        check(!read(new File("/proc/self/maps")).contains("libModernCombat4.so"), "Native game library loaded during WebView check.");
        result.putString("webviewNativeLibraryAbsent", "PASS");
    }

    private String webviewValuePrefix(String generation) { return TEXT + " | " + generation + " | " + webviewKey + " | writerPID="; }

    /** Allows asynchronous provider work time; this delay is not a DOM-storage durability barrier. */
    private void webviewGrace(long deadline) throws Exception {
        long started = SystemClock.elapsedRealtime();
        result.putLong("webviewGraceRequestedMillis", WEBVIEW_GRACE_MILLIS);
        result.putString("webviewGrace", "NON-BARRIER: keeping WebView and process alive; only cold read proves persistence");
        CompletableFuture<Void> elapsed = new CompletableFuture<>();
        bounded(new FutureTask<Void>(() -> {
            checkMainThread();
            check(diagnosticWebView != null, "WebView absent before diagnostic grace.");
            boolean posted = new Handler(Looper.getMainLooper()).postDelayed(() -> {
                try { checkMainThread(); webviewRemaining(deadline); elapsed.complete(null); }
                catch (Throwable error) { elapsed.completeExceptionally(error); }
            }, WEBVIEW_GRACE_MILLIS);
            check(posted, "Main thread refused diagnostic grace callback.");
            return null;
        }), true, webviewRemaining(deadline));
        webviewAwait(elapsed, deadline);
        result.putLong("webviewGraceActualMillis", SystemClock.elapsedRealtime() - started);
    }

    private JSONObject webviewEvaluate(String body, String key, long deadline) throws Exception {
        CompletableFuture<String> evaluated = new CompletableFuture<>();
        String script = "(function(){try{var k=" + key + ";" + body
                + "return JSON.stringify({origin:location.origin,value:localStorage.getItem(k),before:typeof before==='undefined'?null:before});}catch(e){return JSON.stringify({error:String(e)});}})()";
        bounded(new FutureTask<Void>(() -> {
            checkMainThread();
            diagnosticWebView.evaluateJavascript(script, value -> {
                try { checkMainThread(); evaluated.complete(value); }
                catch (Throwable error) { evaluated.completeExceptionally(error); }
            });
            return null;
        }), true, webviewRemaining(deadline));
        Object decoded = new JSONTokener(webviewAwait(evaluated, deadline)).nextValue();
        check(decoded instanceof String, "Unexpected JavaScript callback encoding.");
        JSONObject state = new JSONObject((String) decoded);
        check(!state.has("error"), "DOM storage JavaScript error: " + state.optString("error"));
        check(WEBVIEW_ORIGIN.equals(state.getString("origin")), "DOM storage used an unexpected origin.");
        return state;
    }

    private void destroyDiagnosticWebView() throws Exception {
        bounded(new FutureTask<Void>(() -> {
            checkMainThread();
            if (diagnosticWebView != null) { diagnosticWebView.destroy(); diagnosticWebView = null; }
            return null;
        }), true);
        result.putString("cleanup", "webview-cleanup".equals(mode) ? "PASS: WebView destroyed; only exact key removal requested"
                : "PASS: WebView destroyed; exact key retained for next mode");
        result.putString("webviewDestroyed", "PASS");
    }

    private static void checkMainThread() throws IOException { check(Looper.myLooper() == Looper.getMainLooper(), "WebView callback/task is not on main thread."); }
    private static long webviewRemaining(long deadline) throws IOException {
        long remaining = deadline - SystemClock.elapsedRealtime(); check(remaining > 0, "WebView diagnostic exceeded 25-second deadline."); return remaining;
    }
    private static <T> T webviewAwait(CompletableFuture<T> completion, long deadline) throws Exception {
        try { return completion.get(webviewRemaining(deadline), TimeUnit.MILLISECONDS); }
        catch (TimeoutException timeout) { completion.cancel(false); throw timeout; }
        catch (ExecutionException wrapped) {
            Throwable cause = wrapped.getCause(); if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause; throw new IOException(cause);
        }
    }

    /** A real failed Application bootstrap is required; this mode never changes AppData state or storage. */
    private void unavailable() throws Exception {
        check(context.getApplicationContext() instanceof AppData && !AppData.ready(), "Unavailable mode requires the real failed AppData Application.");
        check(AppData.error() != null && !AppData.error().equals("Game data bootstrap has not run."), "Bootstrap failure was not established.");
        String pkg = context.getPackageName();
        String[] activities = {"MC4", "WebBrowser", "OfflineCheatCatalogActivity", "InGameBrowser", "installer.GameInstaller",
                "iab.GMPActivity", "MyVideoView", "GLiveHTML.GLLiveActivity", "IGPFreemiumActivity", "SplashScreenActivity"};
        check(context.getPackageManager().getPackageInfo(pkg, PackageManager.GET_ACTIVITIES).activities.length == activities.length, "Declared Activity inventory changed.");
        for (String name : activities) unavailableCase("activity." + name, () -> {
            unavailableActivity(pkg + "." + name); return null;
        });
        unavailableCase("receiver.ApplicationSetUp", () -> {
            unavailableReceiver(pkg + ".ApplicationSetUp", new Intent("com.gameloft.android.ApplicationSetUp").putExtra("GA_DEBUG", "phase5-unavailable-check")); return null;
        });
        unavailableCase("receiver.IReferrerReceiver", () -> {
            unavailableReceiver(pkg + ".installer.IReferrerReceiver", new Intent("com.android.vending.INSTALL_REFERRER").putExtra("referrer", "utm_source=phase5-unavailable-check")); return null;
        });
        unavailableCase("provider.KeyProvider.query", () -> {
            unavailableQuery(Uri.parse("content://" + pkg + ".KeyProvider/key")); return null;
        });
        unavailableCase("provider.ZipFileContentProvider.query", () -> {
            unavailableQuery(Uri.parse("content://" + pkg + ".provider.ZipFileContentProvider/")); return null;
        });
        unavailableCase("native_library_absent", () -> {
            check(!read(new File("/proc/self/maps")).contains("libModernCombat4.so"), "Native game library was loaded during failed bootstrap."); return null;
        });
        check(!AppData.ready(), "Unavailable checks changed bootstrap readiness.");
    }

    private void unavailableCase(String name, Callable<Void> action) {
        Bundle progress = new Bundle(); progress.putString("case", name); progress.putString("state", "RUNNING"); sendStatus(0, progress);
        try {
            check(!AppData.ready(), "Unexpected ready bootstrap before negative case.");
            action.call(); passed++; result.putString(name, "PASS"); Log.i(TAG, name + " PASS");
        } catch (Throwable error) {
            failed++; result.putString(name, "FAIL: " + error); result.putString(name + ".trace", Log.getStackTraceString(error)); Log.e(TAG, name + " FAIL", error);
        }
        progress.putString("state", result.getString(name)); sendStatus(0, progress);
    }

    private void unavailableActivity(String className) throws Exception {
        ComponentName component = new ComponentName(context.getPackageName(), className);
        context.getPackageManager().getActivityInfo(component, 0);
        Intent intent = new Intent().setComponent(component).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        String key = "activity." + className.substring(context.getPackageName().length() + 1);
        ActivityMonitor monitor = addMonitor(className, null, false);
        Activity[] current = {null};
        int[] generation = {0};
        try {
            current[0] = bounded(new FutureTask<>(() -> startActivitySync(intent)), false);
            check(current[0] != null && current[0].getClass().getName().equals(className), "Wrong/missing real Activity.");
            result.putString(key + ".stage", "created");
            long selectUntil = SystemClock.elapsedRealtime() + 8000;
            boolean exercised = false;
            while (!exercised) {
                long remaining = selectUntil - SystemClock.elapsedRealtime();
                check(remaining > 0, "No live monitored Activity within 8 seconds after launch.");
                exercised = bounded(new FutureTask<Boolean>(() -> {
                    Activity activity = current[0];
                    recordActivityState(key + ".instance" + generation[0], activity);
                    check(!activity.isFinishing(), "Activity really finished before pause/resume check.");
                    if (activity.isDestroyed() || activity.isChangingConfigurations()) {
                        check(activity.isChangingConfigurations(), "Activity destroyed without configuration change.");
                        Activity replacement = monitor.getLastActivity();
                        if (activity.isDestroyed() && replacement != null && replacement != activity) {
                            check(replacement.getClass().getName().equals(className), "Wrong monitored replacement class.");
                            current[0] = replacement; generation[0]++;
                            result.putInt(key + ".configurationReplacements", generation[0]);
                            result.putString(key + ".stage", "observed-configuration-replacement");
                        }
                        return false;
                    }
                    if (!activity.getWindow().getDecorView().isAttachedToWindow()) return false;
                    callActivityOnPause(activity); result.putString(key + ".stage", "paused");
                    callActivityOnResume(activity); result.putString(key + ".stage", "resumed");
                    result.putString(key + ".testedInstance", activityIdentity(activity)); return true;
                }), true, remaining);
                if (!exercised) SystemClock.sleep(25);
            }
        } finally {
            try { if (current[0] != null) bounded(new FutureTask<Void>(() -> { current[0].finish(); return null; }), true); }
            finally { removeMonitor(monitor); }
        }
        long until = SystemClock.elapsedRealtime() + 8000;
        while (!current[0].isDestroyed() && SystemClock.elapsedRealtime() < until) SystemClock.sleep(25);
        check(current[0].isDestroyed(), "Activity did not destroy within 8 seconds after finish.");
        result.putString(key + ".stage", "destroyed-after-pause-resume");
    }

    private void recordActivityState(String key, Activity activity) {
        result.putString(key + ".identity", activityIdentity(activity));
        result.putBoolean(key + ".isFinishing", activity.isFinishing());
        result.putBoolean(key + ".isDestroyed", activity.isDestroyed());
        result.putBoolean(key + ".isChangingConfigurations", activity.isChangingConfigurations());
    }
    private static String activityIdentity(Activity activity) { return activity.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(activity)); }

    private void unavailableReceiver(String className, Intent intent) throws Exception {
        ComponentName component = new ComponentName(context.getPackageName(), className);
        context.getPackageManager().getReceiverInfo(component, 0);
        BroadcastReceiver receiver = Class.forName(className, true, context.getClassLoader()).asSubclass(BroadcastReceiver.class).getDeclaredConstructor().newInstance();
        intent.setComponent(component);
        bounded(new FutureTask<Void>(() -> { receiver.onReceive(context, intent); return null; }), true);
    }

    private void unavailableQuery(Uri uri) throws Exception {
        check(context.getPackageManager().resolveContentProvider(uri.getAuthority(), 0) != null, "Provider authority is not declared.");
        bounded(new FutureTask<Void>(() -> {
            try (Cursor unexpected = context.getContentResolver().query(uri, null, null, null, null)) {
                throw new IOException("Provider read accepted failed bootstrap: " + uri);
            } catch (IllegalStateException expected) {
                check(AppData.error().equals(expected.getMessage()), "Provider rejected for an unrelated reason: " + expected);
                result.putString("provider." + uri.getAuthority() + ".expectedFailure", expected.toString());
            }
            return null;
        }), false);
    }

    private static <T> T bounded(FutureTask<T> task, boolean mainThread) throws Exception {
        return bounded(task, mainThread, 8000);
    }
    private static <T> T bounded(FutureTask<T> task, boolean mainThread, long timeoutMillis) throws Exception {
        if (mainThread) check(new Handler(Looper.getMainLooper()).post(task), "Main-thread diagnostic post rejected.");
        else { Thread worker = new Thread(task, TAG + "-bounded"); worker.setDaemon(true); worker.start(); }
        try { return task.get(timeoutMillis, TimeUnit.MILLISECONDS); }
        catch (TimeoutException timeout) { task.cancel(!mainThread); throw timeout; }
        catch (ExecutionException wrapped) {
            Throwable cause = wrapped.getCause(); if (cause instanceof Exception) throw (Exception) cause;
            if (cause instanceof Error) throw (Error) cause; throw new IOException(cause);
        }
    }

    private File[] fixture(String name) throws Exception {
        File privateDir = new File(privateFixtures, name), externalDir = new File(externalFixtures, name);
        mkdir(privateDir); mkdir(externalDir);
        put(new File(privateDir, "files/SaveGame.bin"), "fixture-save");
        put(new File(privateDir, "files/CheckPoint.bin"), "fixture-checkpoint");
        put(new File(privateDir, "files/backupSaveFile.dat"), "fixture-backup");
        put(new File(privateDir, "shared_prefs/fixture.xml"), "<?xml version='1.0' encoding='utf-8'?><map><string name='text'>" + TEXT + "</string></map>");
        File database = new File(privateDir, "databases/fixture.db"); mkdir(database.getParentFile());
        try (SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(database, null)) {
            db.execSQL("CREATE TABLE fixture (value TEXT NOT NULL)");
            db.execSQL("INSERT INTO fixture VALUES (?)", new Object[]{"fixture-database"});
        }
        return new File[]{privateDir, externalDir};
    }

    private void linksAndRetries() throws Exception {
        File[] f = fixture("links"); AppData.prepare(f[0], f[1]); verifyLinks(f);
        String[] archiveHashes = new String[GROUPS.length];
        for (int i = 0; i < GROUPS.length; i++) {
            File original = new File(f[0], ".phase5-original-" + GROUPS[i]);
            File archive = new File(f[1], ".phase5-migration-archive/" + GROUPS[i]);
            archiveHashes[i] = AppData.treeHash(archive);
            check(archiveHashes[i].equals(AppData.treeHash(original)), "Original/archive differ: " + GROUPS[i]);
        }
        // Deliberately use a direct stream through the private alias; atomicWrite rejects alias parents.
        put(new File(f[0], "files/SaveGame.bin"), "updated-through-private-alias");
        check(read(new File(f[1], "SaveGame.bin")).equals("updated-through-private-alias"), "Alias write is not external.");
        AppData.atomicWrite(new File(f[1], "shared_prefs/fixture.xml"), ("<map><string name='text'>" + TEXT + " changed</string></map>").getBytes(StandardCharsets.UTF_8));
        try (SQLiteDatabase db = SQLiteDatabase.openDatabase(new File(f[0], "databases/fixture.db").getPath(), null, SQLiteDatabase.OPEN_READWRITE)) {
            db.execSQL("UPDATE fixture SET value=?", new Object[]{"updated-external-database"});
        }
        AppData.prepare(f[0], f[1]); AppData.prepare(f[0], f[1]); verifyLinks(f);
        check(read(new File(f[0], "files/SaveGame.bin")).equals("updated-through-private-alias"), "Retry replaced current save.");
        check(read(new File(f[1], "shared_prefs/fixture.xml")).contains(TEXT + " changed"), "Retry replaced live prefs.");
        try (SQLiteDatabase db = SQLiteDatabase.openDatabase(new File(f[1], "databases/fixture.db").getPath(), null, SQLiteDatabase.OPEN_READONLY);
             Cursor row = db.rawQuery("SELECT value FROM fixture", null)) {
            check(row.moveToFirst() && row.getString(0).equals("updated-external-database"), "Retry replaced live SQLite.");
        }
        for (int i = 0; i < GROUPS.length; i++)
            check(archiveHashes[i].equals(AppData.treeHash(new File(f[1], ".phase5-migration-archive/" + GROUPS[i]))), "Retry changed archive.");
        result.putString("links_two_retries.archive_files_sha256", archiveHashes[0]);
    }

    private void corruption(boolean archive) throws Exception {
        File[] f = fixture(archive ? "archive" : "marker"); AppData.prepare(f[0], f[1]);
        String live = AppData.fileHash(new File(f[1], "SaveGame.bin"));
        String retained = AppData.treeHash(new File(f[0], ".phase5-original-files"));
        File damaged = new File(f[1], archive ? ".phase5-migration-archive/files/SaveGame.bin" : ".phase5-data-links-v1");
        AppData.atomicWrite(damaged, "deliberate-own-fixture-corruption".getBytes(StandardCharsets.UTF_8));
        boolean rejected = false;
        try { AppData.prepare(f[0], f[1]); }
        catch (IOException error) {
            String expected = archive ? "archive" : "marker";
            check(error.getMessage() != null && error.getMessage().toLowerCase(Locale.ROOT).contains(expected), "Unrelated rejection: " + error);
            result.putString("corrupt_" + expected + ".expectedFailure", error.toString()); rejected = true;
        }
        check(rejected, "Corrupt fixture accepted.");
        check(live.equals(AppData.fileHash(new File(f[1], "SaveGame.bin"))), "Corruption check changed live save.");
        check(retained.equals(AppData.treeHash(new File(f[0], ".phase5-original-files"))), "Corruption check changed retained originals.");
    }

    private void interrupted(boolean active) throws Exception {
        File[] f = fixture(active ? "interrupted-active" : "interrupted-retained");
        File live = new File(f[0], "files"), original = new File(f[0], ".phase5-original-files");
        AppData.copySnapshot(live, new File(f[1], ".phase5-migration-archive/files"));
        AppData.mergeFiles(live, f[1]);
        Os.rename(live.getPath(), original.getPath());
        Os.symlink(f[1].getCanonicalPath(), new File(f[0], active ? "files" : ".phase5-link-files").getPath());
        AppData.copySnapshot(new File(f[0], "shared_prefs"), new File(f[1], ".phase5-stage-shared_prefs"));
        AppData.atomicWrite(new File(f[1], "SaveGame.bin"), "current-before-recovery".getBytes(StandardCharsets.UTF_8));
        AppData.prepare(f[0], f[1]); verifyLinks(f);
        check(read(new File(f[0], "files/SaveGame.bin")).equals("current-before-recovery"), "Recovery restored a stale private save.");
        check(read(new File(original, "SaveGame.bin")).equals("fixture-save"), "Recovery altered retained original.");
        check(!new File(f[1], ".phase5-stage-shared_prefs").exists(), "Consistent stage was not activated.");
        AppData.prepare(f[0], f[1]);
    }

    private void preferences() throws Exception {
        AppData.requireReady();
        File physical = new File(externalRoot, "shared_prefs/" + prefsName + ".xml");
        sameFile(new File(dataRoot, "shared_prefs"), physical.getParentFile());
        check(!physical.exists() && !new File(physical.getPath() + ".bak").exists(), "Preferences namespace collision.");
        prefsOpened = true;
        SharedPreferences prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE);
        check(prefs.edit().putInt("i", 42).putLong("l", LARGE).putBoolean("b", true).putString("text", TEXT).commit(), "Preferences commit failed.");
        verifyPrefs(prefs, LARGE, TEXT); verifyPrefsXml(physical, LARGE, TEXT);
        String initialHash = AppData.fileHash(physical);
        check(prefs.edit().putLong("l", LARGE + 1).putString("text", TEXT + " changed").commit(), "Preferences update failed.");
        verifyPrefs(context.getSharedPreferences(prefsName, Context.MODE_PRIVATE), LARGE + 1, TEXT + " changed");
        verifyPrefsXml(physical, LARGE + 1, TEXT + " changed");
        check(!initialHash.equals(AppData.fileHash(physical)), "Physical preferences XML did not change.");
        sameFile(new File(dataRoot, "shared_prefs/" + prefsName + ".xml"), physical);
        result.putString("preferences.physicalXml", physical.getPath());
        result.putString("preferences.sha256", AppData.fileHash(physical));
    }

    private static void verifyPrefs(SharedPreferences prefs, long large, String text) throws Exception {
        check(prefs.getInt("i", 0) == 42 && prefs.getLong("l", 0) == large && prefs.getBoolean("b", false)
                && text.equals(prefs.getString("text", null)), "Preference values/types changed.");
        Map<String, ?> all = prefs.getAll();
        check(all.get("i") instanceof Integer && all.get("l") instanceof Long && all.get("b") instanceof Boolean
                && all.get("text") instanceof String, "getAll types changed.");
    }

    private static void verifyPrefsXml(File physical, long large, String text) throws Exception {
        int seen = 0;
        try (FileInputStream input = new FileInputStream(physical)) {
            XmlPullParser parser = Xml.newPullParser(); parser.setInput(input, "UTF-8");
            while (parser.next() != XmlPullParser.END_DOCUMENT) {
                if (parser.getEventType() != XmlPullParser.START_TAG) continue;
                String key = parser.getAttributeValue(null, "name"), type = parser.getName();
                if ("i".equals(key)) { check(type.equals("int") && "42".equals(parser.getAttributeValue(null, "value")), "Disk int mismatch."); seen++; }
                if ("l".equals(key)) { check(type.equals("long") && Long.toString(large).equals(parser.getAttributeValue(null, "value")), "Disk long mismatch."); seen++; }
                if ("b".equals(key)) { check(type.equals("boolean") && "true".equals(parser.getAttributeValue(null, "value")), "Disk boolean mismatch."); seen++; }
                if ("text".equals(key)) { check(type.equals("string") && text.equals(parser.nextText()), "Disk UTF-8 string mismatch."); seen++; }
            }
        }
        check(seen == 4, "Physical preferences XML is incomplete.");
    }

    private void sqlite() throws Exception {
        AppData.requireReady();
        File physical = new File(externalRoot, "databases/" + databaseName);
        sameFile(new File(dataRoot, "databases"), physical.getParentFile());
        for (String suffix : new String[]{"", "-journal", "-wal", "-shm"})
            check(!new File(physical.getPath() + suffix).exists(), "SQLite namespace collision.");
        databaseOpened = true;
        try (SQLiteDatabase db = context.openOrCreateDatabase(databaseName, Context.MODE_PRIVATE, null)) {
            try { result.putBoolean("sqlite.walEnableReturn", db.enableWriteAheadLogging()); }
            catch (RuntimeException unsupported) { result.putString("sqlite.walEnableException", unsupported.toString()); }
            result.putBoolean("sqlite.walEnabledFlag", db.isWriteAheadLoggingEnabled());
            result.putString("sqlite.actualJournalMode", scalar(db, "PRAGMA journal_mode"));
            db.execSQL("CREATE TABLE fixture (id INTEGER PRIMARY KEY, text TEXT NOT NULL, number INTEGER NOT NULL)");
            db.execSQL("INSERT INTO fixture VALUES (?, ?, ?)", new Object[]{1, TEXT, LARGE});
            try (Cursor row = db.rawQuery("SELECT text, number FROM fixture WHERE id=1", null)) {
                check(row.moveToFirst() && TEXT.equals(row.getString(0)) && row.getLong(1) == LARGE, "SQLite insert/query mismatch.");
            }
            ContentValues values = new ContentValues(); values.put("text", TEXT + " changed"); values.put("number", LARGE + 1);
            check(db.update("fixture", values, "id=?", new String[]{"1"}) == 1, "SQLite update failed.");
            try (Cursor row = db.rawQuery("SELECT text, number FROM fixture WHERE id=1", null)) {
                check(row.moveToFirst() && (TEXT + " changed").equals(row.getString(0)) && row.getLong(1) == LARGE + 1, "SQLite updated values did not persist.");
            }
            check(db.delete("fixture", "id=?", new String[]{"1"}) == 1, "SQLite delete failed.");
            check("0".equals(scalar(db, "SELECT count(*) FROM fixture")), "SQLite deleted row survived.");
            db.execSQL("INSERT INTO fixture VALUES (?, ?, ?)", new Object[]{2, TEXT + " reopened", LARGE + 2});
            sameFile(context.getDatabasePath(databaseName), physical);
            result.putString("sqlite.sidecarsWhileOpen", sidecars(physical));
            result.putString("sqlite.integrityBeforeClose", scalar(db, "PRAGMA integrity_check"));
            check("ok".equals(result.getString("sqlite.integrityBeforeClose")), "SQLite integrity before close failed.");
        }
        try (SQLiteDatabase db = context.openOrCreateDatabase(databaseName, Context.MODE_PRIVATE, null);
             Cursor row = db.rawQuery("SELECT text, number FROM fixture WHERE id=2", null)) {
            check(row.moveToFirst() && (TEXT + " reopened").equals(row.getString(0)) && row.getLong(1) == LARGE + 2, "SQLite close/reopen lost committed row.");
            result.putString("sqlite.reopenJournalMode", scalar(db, "PRAGMA journal_mode"));
            result.putString("sqlite.integrityAfterReopen", scalar(db, "PRAGMA integrity_check"));
            check("ok".equals(result.getString("sqlite.integrityAfterReopen")), "SQLite reopen integrity failed.");
        }
        sameFile(context.getDatabasePath(databaseName), physical);
        result.putString("sqlite.physicalDatabase", physical.getPath());
        result.putString("sqlite.sha256AfterClose", AppData.fileHash(physical));
    }

    private static String scalar(SQLiteDatabase db, String sql) throws Exception {
        try (Cursor cursor = db.rawQuery(sql, null)) { check(cursor.moveToFirst(), "Empty SQLite scalar: " + sql); return cursor.getString(0); }
    }
    private static String sidecars(File database) {
        StringBuilder text = new StringBuilder();
        for (String suffix : new String[]{"", "-journal", "-wal", "-shm"}) {
            File file = new File(database.getPath() + suffix);
            text.append(file.getName()).append('=').append(file.exists() ? file.length() : -1).append(';');
        }
        return text.toString();
    }
    private static void verifyLinks(File[] fixture) throws Exception {
        for (String group : GROUPS) {
            File logical = new File(fixture[0], group), physical = group.equals("files") ? fixture[1] : new File(fixture[1], group);
            check(OsConstants.S_ISLNK(Os.lstat(logical.getPath()).st_mode), "Missing real symbolic link: " + group);
            check(Os.readlink(logical.getPath()).equals(physical.getCanonicalPath()), "Wrong link target: " + group);
            sameFile(logical, physical);
        }
    }
    private static void sameFile(File logical, File physical) throws Exception {
        StructStat a = Os.stat(logical.getPath()), b = Os.stat(physical.getPath());
        check(a.st_dev == b.st_dev && a.st_ino == b.st_ino, "Logical/physical device-inode mismatch: " + logical);
    }
    private static void mkdir(File directory) throws IOException {
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("Cannot create fixture directory: " + directory);
    }
    private static void put(File file, String text) throws IOException {
        mkdir(file.getParentFile());
        try (FileOutputStream output = new FileOutputStream(file)) { output.write(text.getBytes(StandardCharsets.UTF_8)); output.flush(); output.getFD().sync(); }
    }
    private static String read(File file) throws IOException {
        java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
        try (FileInputStream input = new FileInputStream(file)) { byte[] buffer = new byte[8192]; int count; while ((count = input.read(buffer)) != -1) bytes.write(buffer, 0, count); }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }
    private static void check(boolean condition, String message) throws IOException { if (!condition) throw new IOException(message); }

    private void cleanup() throws Exception {
        // Standard APIs delete only the exact UUID namespace. Verify parents first, including aliases.
        if (prefsOpened) {
            sameFile(new File(dataRoot, "shared_prefs"), new File(externalRoot, "shared_prefs"));
            check(prefsName.equals(prefix + ".prefs"), "Preferences cleanup name changed.");
            check(context.deleteSharedPreferences(prefsName), "Cannot delete own preferences namespace.");
            check(!new File(externalRoot, "shared_prefs/" + prefsName + ".xml").exists()
                    && !new File(externalRoot, "shared_prefs/" + prefsName + ".xml.bak").exists(), "Own preferences cleanup incomplete.");
        }
        if (databaseOpened) {
            sameFile(new File(dataRoot, "databases"), new File(externalRoot, "databases"));
            check(databaseName.equals(prefix + ".db"), "Database cleanup name changed.");
            boolean exists = false;
            for (String suffix : new String[]{"", "-journal", "-wal", "-shm"})
                exists |= new File(externalRoot, "databases/" + databaseName + suffix).exists();
            if (exists) check(context.deleteDatabase(databaseName), "Cannot delete own SQLite namespace.");
            for (String suffix : new String[]{"", "-journal", "-wal", "-shm"})
                check(!new File(externalRoot, "databases/" + databaseName + suffix).exists(), "Own SQLite cleanup incomplete.");
        }
        deleteOwnedRoot(privateFixtures, dataRoot); deleteOwnedRoot(externalFixtures, externalRoot);
    }

    private void deleteOwnedRoot(File owned, File expectedParent) throws Exception {
        if (owned == null) return;
        check(owned.getName().equals(prefix) && owned.getParentFile().getCanonicalFile().equals(expectedParent), "Unsafe fixture cleanup root.");
        StructStat stat;
        try { stat = Os.lstat(owned.getPath()); }
        catch (ErrnoException absent) { if (absent.errno == OsConstants.ENOENT) return; throw absent; }
        check(OsConstants.S_ISDIR(stat.st_mode), "Fixture cleanup root is not a real directory.");
        File canonical = owned.getCanonicalFile();
        check(canonical.equals(new File(expectedParent, prefix)), "Fixture cleanup root escaped parent.");
        deleteNoFollow(owned, canonical);
    }

    private static void deleteNoFollow(File file, File approvedRoot) throws Exception {
        StructStat stat = Os.lstat(file.getPath());
        File parent = file.getParentFile().getCanonicalFile();
        check(file.equals(approvedRoot) || parent.equals(approvedRoot) || parent.getPath().startsWith(approvedRoot.getPath() + File.separator), "Fixture child escaped cleanup boundary.");
        if (OsConstants.S_ISDIR(stat.st_mode)) {
            File canonical = file.getCanonicalFile();
            check(canonical.equals(approvedRoot) || canonical.getPath().startsWith(approvedRoot.getPath() + File.separator), "Real fixture directory escaped boundary.");
            File[] children = file.listFiles(); check(children != null, "Cannot list own fixture directory.");
            for (File child : children) deleteNoFollow(child, approvedRoot);
        } else check(OsConstants.S_ISREG(stat.st_mode) || OsConstants.S_ISLNK(stat.st_mode), "Unexpected fixture inode type.");
        // A symlink is unlinked here; its target is never listed, followed or deleted.
        check(file.delete(), "Cannot delete own fixture path: " + file);
    }
}
