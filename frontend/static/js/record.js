/**
 * Record Complaint Client Script
 * Handles toggling between Live Recording and Audio File Upload,
 * microphone streaming via MediaRecorder, timer updates, and populating form files.
 */

function showRecord() {
    document.getElementById("recordSection").style.display = "block";
    document.getElementById("uploadSection").style.display = "none";
}

function showUpload() {
    document.getElementById("recordSection").style.display = "none";
    document.getElementById("uploadSection").style.display = "block";
}

let mediaRecorder;
let chunks = [];
let timer;
let seconds = 0;
let stream;

async function startRecording() {
    if (mediaRecorder && mediaRecorder.state === "recording") {
        return;
    }

    try {
        stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        chunks = [];

        mediaRecorder.ondataavailable = function(e) {
            chunks.push(e.data);
        };

        mediaRecorder.onstop = function() {
            const blob = new Blob(chunks, { type: "audio/webm" });
            const player = document.getElementById("player");
            if (player) {
                player.src = URL.createObjectURL(blob);
            }

            // Create a File object from the recorded blob
            const file = new File([blob], "recorded.webm", { type: "audio/webm" });

            // Put the file into the hidden input
            const dt = new DataTransfer();
            dt.items.add(file);
            document.getElementById("recordedAudio").files = dt.files;
        };

        mediaRecorder.start();
        document.getElementById("status").textContent = "🔴 Recording...";

        seconds = 0;
        timer = setInterval(function() {
            seconds++;
            const m = Math.floor(seconds / 60);
            const s = seconds % 60;
            document.getElementById("timer").textContent =
                String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
        }, 1000);

    } catch (err) {
        console.error("Microphone access denied or not available:", err);
        document.getElementById("status").textContent = "❌ Microphone access error: " + err.message;
    }
}

function stopRecording() {
    if (!mediaRecorder) return;

    if (mediaRecorder.state === "recording") {
        mediaRecorder.stop();
    }
    clearInterval(timer);

    if (stream) {
        stream.getTracks().forEach(function(track) {
            track.stop();
        });
    }

    document.getElementById("status").textContent = "✅ Recording Completed";
}
