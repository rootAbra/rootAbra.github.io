// Configuración de marked.js y carga de contenido Markdown
document.addEventListener('DOMContentLoaded', function() {
  // Configuración de marked.js
  if (typeof marked !== 'undefined') {
    marked.setOptions({
      highlight: function(code, lang) {
        if (lang && hljs.getLanguage(lang)) {
          return hljs.highlight(code, { language: lang }).value;
        }
        return hljs.highlightAuto(code).value;
      },
      breaks: true,
      gfm: true
    });
  }

  // Cargar el archivo Markdown
  async function loadMarkdown() {
    const contentDiv = document.getElementById('markdown-content');
    if (!contentDiv) return;

    const markdownFile = contentDiv.getAttribute('data-markdown-file') || 'content.md';

    try {
      const response = await fetch(markdownFile);
      
      if (!response.ok) {
        throw new Error('No se pudo cargar el archivo Markdown');
      }
      
      const markdownText = await response.text();
      
      // Renderizar el Markdown
      contentDiv.innerHTML = marked.parse(markdownText);
      
      // Aplicar syntax highlighting a los bloques de código
      document.querySelectorAll('pre code').forEach((block) => {
        if (typeof hljs !== 'undefined') {
          hljs.highlightElement(block);
        }
      });
      
    } catch (error) {
      console.error('Error cargando el Markdown:', error);
      contentDiv.innerHTML = `
        <p style="text-align: center; color: #ff453a; padding: 2rem;">
          Error al cargar el contenido del writeup.<br>
          Asegúrate de que existe el archivo <code>${markdownFile}</code> en esta carpeta.
        </p>
      `;
    }
  }

  // Cargar el contenido cuando la página esté lista
  if (document.getElementById('markdown-content')) {
    loadMarkdown();
  }
});