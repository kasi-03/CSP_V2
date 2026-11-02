/**
 * Dashboard Client Script
 * Handles complaint audio playback modal and live table filtering.
 */

function playAudio(audioUrl) {
    const modal = document.getElementById("audioModal");
    const player = document.getElementById("audioPlayer");

    player.src = audioUrl;
    player.load();
    player.play().catch(function(e) {
        console.warn("Autoplay was prevented or audio failed:", e);
    });

    modal.style.display = "block";
}

function closeAudio() {
    const modal = document.getElementById("audioModal");
    const player = document.getElementById("audioPlayer");

    player.pause();
    player.currentTime = 0;
    modal.style.display = "none";
}

window.onclick = function(event) {
    const modal = document.getElementById("audioModal");
    if (event.target === modal) {
        closeAudio();
    }
};

function searchTable() {
    const input = document.getElementById("searchInput");
    const filter = input.value.toLowerCase();
    const table = document.querySelector("table");
    if (!table) return;

    const rows = table.getElementsByTagName("tr");
    for (let i = 1; i < rows.length; i++) {
        const text = rows[i].innerText.toLowerCase();
        rows[i].style.display = text.includes(filter) ? "" : "none";
    }
}
