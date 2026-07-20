import SwiftUI
import WidgetKit

@main
struct QeliWidgetsBundle: WidgetBundle {
    var body: some Widget {
        QeliStatusWidget()
        if #available(iOS 18.0, *) {
            QeliConnectionControl()
        }
    }
}
