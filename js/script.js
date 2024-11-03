async function loadMarkdown() {
    const response = await fetch('writeups/writeup1.md'); // Change to your desired Markdown file
    const text = await response.text();
    document.getElementById('content').innerHTML = marked(text);
    document.querySelectorAll('pre code').forEach(el => {
        hljs.highlightElement(el);
    });
}

// Load Markdown content when the page is ready
loadMarkdown();
