import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import smali_reachability as reachability


class ManifestRootTests(unittest.TestCase):
    def test_manifest_component_name_forms_are_roots(self):
        with tempfile.TemporaryDirectory() as temp:
            tree = Path(temp)
            (tree / "res" / "layout").mkdir(parents=True)
            (tree / "AndroidManifest.xml").write_text(
                """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                    package="com.example.game">
                    <application android:name=".GameApplication">
                        <activity android:name=".MainActivity" />
                        <activity android:name="LocalActivity" />
                        <activity android:name="com.vendor.LoginActivity" />
                        <activity-alias android:name=".LauncherAlias"
                            android:targetActivity=".MainActivity" />
                        <service android:name="Service" />
                    </application>
                </manifest>""",
                encoding="utf-8",
            )
            (tree / "res" / "layout" / "widget.xml").write_text(
                "<com.example.game.CustomView />", encoding="utf-8"
            )

            roots = reachability.names_in_xml(str(tree))

        expected = {
            "com/example/game/GameApplication",
            "com/example/game/MainActivity",
            "com/example/game/LocalActivity",
            "com/vendor/LoginActivity",
            "com/example/game/LauncherAlias",
            "com/example/game/Service",
            "com/example/game/CustomView",
        }
        self.assertTrue(expected.issubset(roots), expected - roots)

    def test_current_relative_manifest_components_are_not_orphans(self):
        game = Path(__file__).resolve().parents[2]
        app = game / "app"
        roots = reachability.names_in_xml(str(app))
        classes = reachability.index_classes(str(app))

        for component in (
            "com/gameloft/android/ANMP/GloftM4HM/iab/GMPActivity",
            "com/gameloft/android/ANMP/GloftM4HM/ZipFileContentProvider",
            "com/gameloft/android/ANMP/GloftM4HM/installer/IReferrerReceiver",
        ):
            with self.subTest(component=component):
                self.assertIn(component, roots)
                self.assertIn(component, classes)


if __name__ == "__main__":
    unittest.main()
