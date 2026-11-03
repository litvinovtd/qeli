import unittest
import xml.etree.ElementTree as ET
from audit_android_release_ui import await_import_button
from android_lab_ui import AndroidVpnSettings

def tree(selected=False,ready=False):
    root=ET.Element('hierarchy')
    ET.SubElement(root,'node',text='Profiles',selected=str(selected).lower())
    if ready:ET.SubElement(root,'node',**{'resource-id':'com.qeli:id/btnImport'})
    return root

class ReleaseUiTransitionTest(unittest.TestCase):
    def run_transition(self,states):
        taps=[];dumps=[]
        class Ui:
            text_node=staticmethod(AndroidVpnSettings.text_node)
            def tap(self,n):taps.append(n)
        def dump(label):dumps.append(label);return states.pop(0)
        result=await_import_button(Ui(),states.pop(0),dump)
        return result,taps,dumps

    def test_swallowed_first_tap_is_retried_after_observed_unselected_state(self):
        button,taps,dumps=self.run_transition([tree(),tree(),tree(True,True)])
        self.assertEqual(button.get('resource-id'),'com.qeli:id/btnImport')
        self.assertEqual(len(taps),2)
        self.assertEqual(len(dumps),2)

    def test_selected_tab_loading_is_observed_without_repeated_taps(self):
        button,taps,dumps=self.run_transition([tree(),tree(True),tree(True,True)])
        self.assertEqual(len(taps),1)
        self.assertEqual(len(dumps),2)

    def test_missing_button_cannot_be_qualified_by_selected_tab_alone(self):
        with self.assertRaisesRegex(AssertionError,'bounded tab observation'):
            self.run_transition([tree(True) for _ in range(6)])

if __name__=='__main__':unittest.main()
