const output = document.querySelector("#output");
const pixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAAK0lEQVR4nO3NMQEAAAgDINc/9K3hHFQgE1m1ZcuWLVu2bNmyZcuWLVu2bNmy5Q5s4gFBNdmgAAAAAElFTkSuQmCC";

function reset() {
  output.replaceChildren();
}

function deny(delay = 350) {
  setTimeout(() => {
    const message = document.createElement("p");
    message.textContent = "非常抱歉，生成的图片可能违反了关于与第三方内容相似性的防护限制。如果你认为此判断有误，请重试或修改提示语。";
    output.replaceChildren(message);
  }, delay);
}

document.querySelector("#l0").addEventListener("click", () => {
  reset();
  deny();
});

document.querySelector("#l2").addEventListener("click", () => {
  reset();
  const image = document.createElement("img");
  image.alt = "unavailable preview";
  image.src = "https://example.invalid/generated/preview.png?token=do-not-store";
  output.append(image);
  deny();
});

document.querySelector("#l3").addEventListener("click", () => {
  reset();
  const image = document.createElement("img");
  image.alt = "local test pattern";
  image.src = pixel;
  output.append(image);
  deny();
});
