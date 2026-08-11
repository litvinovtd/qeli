package com.qeli

import android.os.Bundle
import android.view.ViewGroup
import android.widget.FrameLayout
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.google.android.material.button.MaterialButton
import kotlin.math.min

/**
 * Compact QR capture surface used instead of ZXing's full-screen portrait activity.
 *
 * The camera remains orientation-aware, but its preview is measured as a square inside a
 * floating dialog. This avoids stretching the scanner over the whole application window on
 * phones and avoids an excessively large camera sheet on tablets.
 */
class QrCaptureActivity : CaptureActivity() {
    override fun initializeContent(): DecoratedBarcodeView {
        setContentView(R.layout.activity_qr_scanner)
        return findViewById(R.id.zxing_barcode_scanner)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setFinishOnTouchOutside(false)
        findViewById<MaterialButton>(R.id.qr_cancel).setOnClickListener { finish() }

        // Dialog themes otherwise use a platform-dependent minimum width. Keep the scanner
        // comfortable on a phone but bounded on tablets and in landscape.
        window.decorView.post {
            val width = min((resources.displayMetrics.widthPixels * 0.92f).toInt(), dp(520))
            window.setLayout(width, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}

/** A parent that gives the ZXing preview a real 1:1 viewport in every orientation. */
class SquareScannerFrame @JvmOverloads constructor(
    context: android.content.Context,
    attrs: android.util.AttributeSet? = null,
) : FrameLayout(context, attrs) {
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val heightMode = MeasureSpec.getMode(heightMeasureSpec)
        val heightLimit = MeasureSpec.getSize(heightMeasureSpec)
        val size = if (heightMode == MeasureSpec.UNSPECIFIED || heightLimit == 0) {
            width
        } else {
            min(width, heightLimit)
        }
        val exact = MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY)
        super.onMeasure(exact, exact)
    }
}
