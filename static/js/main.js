let stream = null;

async function startCamera() {
    const video = document.getElementById('cameraVideo');
    const container = document.getElementById('cameraContainer');
    try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" } });
        video.srcObject = stream;
        container.classList.remove('hidden');
    } catch (err) {
        alert("Camera permission denied or camera not available.");
    }
}

function captureSelfie() {
    const video = document.getElementById('cameraVideo');
    const canvas = document.getElementById('cameraCanvas');
    const preview = document.getElementById('selfiePreview');
    const fileInput = document.getElementById('selfie');

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);

    canvas.toBlob((blob) => {
        const file = new File([blob], "live_selfie.jpg", { type: "image/jpeg" });
        const dt = new DataTransfer();
        dt.items.add(file);
        fileInput.files = dt.files;
        preview.src = canvas.toDataURL('image/jpeg');
        preview.classList.remove('hidden');
        stopCamera();
    }, 'image/jpeg');
}

function stopCamera() {
    if (stream) {
        stream.getTracks().forEach(track => track.stop());
    }
    const container = document.getElementById('cameraContainer');
    if (container) container.classList.add('hidden');
}