package com.qeli

import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.FrameLayout
import com.journeyapps.barcodescanner.Size
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import com.google.android.material.button.MaterialButton
import kotlin.math.min
import kotlin.math.roundToInt

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
        return scanner
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setFinishOnTouchOutside(false)
        findViewById<MaterialButton>(R.id.qr_cancel).setOnClickListener { finish() }
    }

    override fun onStart() {
        super.onStart()
        // CaptureActivity opens the camera in onResume(). Apply the final dialog and framing
        // geometry first: resizing the window from a decorView.post callback used to leave
        // ZXing's already-calculated framing rect at the old width, visibly shifted left.
        applyScannerGeometry()
    }

    private fun applyScannerGeometry() {
        val width = min((resources.displayMetrics.widthPixels * 0.92f).toInt(), dp(520))
        window.setGravity(Gravity.CENTER)
        window.setLayout(width, ViewGroup.LayoutParams.WRAP_CONTENT)

        // Set an explicit square crop before the preview starts. CameraPreview centres an
        // explicit framing size in its actual viewport, so both the drawn target and the
        // decoder crop share the same centre on narrow phones, tablets and landscape.
        val previewWidth = (width - dp(32)).coerceAtLeast(dp(180))
        val target = (previewWidth * 0.70f).roundToInt()
        scanner.barcodeView.setFramingRectSize(Size(target, target))
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
