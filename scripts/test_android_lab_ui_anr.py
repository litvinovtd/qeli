import tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from android_lab_ui import AndroidVpnSettings

ANR='<hierarchy><node text="Close app" resource-id="android:id/aerr_close" bounds="[0,0][10,10]"/><node text="Wait" resource-id="android:id/aerr_wait" bounds="[10,0][20,10]"/></hierarchy>'
READY='<hierarchy><node text="Always-on VPN" package="com.android.settings"/></hierarchy>'

class AndroidUiAnrTest(unittest.TestCase):
    def test_wait_preserves_original_xml_and_returns_fresh_ready_tree(self):
        self.run_case([ANR,READY],False)

    def test_repeated_anr_is_bounded_and_never_admitted_as_ready(self):
        self.run_case([ANR,ANR,ANR],True)

    def run_case(self,trees,fail):
        taps=[];result={}
        def arun(*args,**kw):
            if 'cat' in args:output=trees.pop(0)
            else:output='UI hierchary dumped'
            if 'tap' in args:taps.append(args[-2:])
            return types.SimpleNamespace(returncode=0,stdout=output,stderr='')
        with tempfile.TemporaryDirectory() as tmp,patch('android_lab_ui.time.sleep'):
            p=Path(tmp);ui=AndroidVpnSettings(arun,p,result,'Qeli')
            if fail:
                with self.assertRaisesRegex(AssertionError,'fresh XML after3'):ui.ui('switch-toggled')
                self.assertEqual(len(list(p.glob('*-anr.xml'))),3)
                self.assertFalse((p/'ui-01-switch-toggled.xml').exists())
            else:
                tree=ui.ui('switch-toggled')
                self.assertEqual(tree.find('node').get('text'),'Always-on VPN')
                self.assertEqual((p/'ui-01-switch-toggled-attempt1-anr.xml').read_text(),ANR)
                self.assertEqual((p/'ui-01-switch-toggled.xml').read_text(),READY)
            self.assertTrue(taps)
            self.assertTrue(all(x==('15','5') for x in taps))
            self.assertEqual(len(result['ui_anr_waits']),len(taps))

if __name__=='__main__':unittest.main()
