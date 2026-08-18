package com.qeli

import android.os.Bundle
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
    private lateinit var scanner: DecoratedBarcodeView

    override fun initializeContent(): DecoratedBarcodeView {
        setContentView(R.layout.activity_qr_scanner)
        scanner = findViewById(R.id.zxing_barcode_scanner)
        // The entire visible square is the decoder crop. A runtime window resize used to leave
        // ZXing with stale coordinates and a visibly displaced 70% target on some OEM builds.
        scanner.barcodeView.setMarginFraction(0.0)
        return scanner
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setFinishOnTouchOutside(false)
        findViewById<MaterialButton>(R.id.qr_cancel).setOnClickListener { finish() }
    }
}

/** A parent that gives the ZXing preview a real 1:1 viewport in every orientation. */
class SquareScannerFrame @JvmOverloads constructor(
    context: android.content.Context,
    attrs: android.util.AttributeSet? = null,
) : FrameLayout(context, attrs) {
    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        // Size the dialog through normal content measurement instead of resizing its Window.
        // ZXing therefore receives the final viewport coordinates on its very first layout.
        val dialogWidth = min(
            (resources.displayMetrics.widthPixels * 0.92f).toInt(),
            dp(520),
        )
        val desiredWidth = (dialogWidth - dp(32)).coerceAtLeast(dp(180))
        val desiredHeight = (resources.displayMetrics.heightPixels - dp(152))
            .coerceAtLeast(dp(180))
        val desired = min(desiredWidth, desiredHeight)
        val widthLimit = if (MeasureSpec.getMode(widthMeasureSpec) == MeasureSpec.UNSPECIFIED) {
            desired
        } else {
            MeasureSpec.getSize(widthMeasureSpec)
        }
        val heightMode = MeasureSpec.getMode(heightMeasureSpec)
        val heightLimit = if (heightMode == MeasureSpec.UNSPECIFIED) {
            desired
        } else {
            MeasureSpec.getSize(heightMeasureSpec)
        }
        val size = min(desired, min(widthLimit, heightLimit))
        val exact = MeasureSpec.makeMeasureSpec(size, MeasureSpec.EXACTLY)
        super.onMeasure(exact, exact)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
