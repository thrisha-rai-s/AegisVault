
function showTab(type) {

    const textForm = document.getElementById("textForm");
    const imageForm = document.getElementById("imageForm");

    const textTab = document.getElementById("textTab");
    const imageTab = document.getElementById("imageTab");

    if (type === "text") {
        textForm.style.display = "block";
        imageForm.style.display = "none";

        textTab.classList.add("active");
        imageTab.classList.remove("active");

        document.getElementById("image").required = false;
        document.getElementById("user_text").required = true;

    } else {
        textForm.style.display = "none";
        imageForm.style.display = "block";

        imageTab.classList.add("active");
        textTab.classList.remove("active");

        document.getElementById("image").required = true;
        document.getElementById("user_text").required = false;
    }
}


const imageInput = document.getElementById("image");

if (imageInput) {
    imageInput.addEventListener("change", function () {

        const fileName = this.files.length
            ? this.files[0].name
            : "No image selected";

        document.getElementById("fileName").textContent = fileName;
    });
}
