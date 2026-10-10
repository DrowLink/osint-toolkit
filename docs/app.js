// OSINT Toolkit Documentation Interactive Scripts
document.addEventListener("DOMContentLoaded", () => {
  // 1. Copy to Clipboard for all code snippets
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const codeBlock = btn.closest(".code-block");
      const codeEl = codeBlock ? codeBlock.querySelector("pre code") : null;
      if (!codeEl) return;

      const text = codeEl.innerText.trim();
      try {
        await navigator.clipboard.writeText(text);
        const originalHtml = btn.innerHTML;
        btn.innerHTML = `<span style="color: #10b981;">✔ Copied!</span>`;
        setTimeout(() => {
          btn.innerHTML = originalHtml;
        }, 2000);
      } catch (err) {
        console.error("Clipboard copy failed:", err);
      }
    });
  });

  // 2. Mobile Menu Toggle
  const mobileToggle = document.querySelector(".mobile-toggle");
  const sidebar = document.querySelector(".sidebar");
  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
    });

    // Close when clicking a link on mobile
    sidebar.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        if (window.innerWidth <= 820) {
          sidebar.classList.remove("open");
        }
      });
    });
  }

  // 3. Search Focus Shortcut (Cmd+K / Ctrl+K)
  const searchInput = document.getElementById("doc-search");
  window.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "k") {
      e.preventDefault();
      if (searchInput) {
        searchInput.focus();
        searchInput.select();
      }
    }
  });

  // 4. Live Search Filter for sections & platforms
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      const query = e.target.value.toLowerCase().trim();
      const sections = document.querySelectorAll("section");
      const platformRows = document.querySelectorAll("#platforms-table tbody tr");

      if (!query) {
        sections.forEach((sec) => (sec.style.display = ""));
        platformRows.forEach((row) => (row.style.display = ""));
        return;
      }

      // Filter platform table if open
      platformRows.forEach((row) => {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(query) ? "" : "none";
      });

      // Filter sections
      sections.forEach((sec) => {
        const text = sec.innerText.toLowerCase();
        sec.style.display = text.includes(query) ? "" : "none";
      });
    });
  }

  // 5. Platform Category Filter
  const filterBtns = document.querySelectorAll(".filter-btn");
  const platformRows = document.querySelectorAll("#platforms-table tbody tr");

  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      const category = btn.getAttribute("data-category");
      platformRows.forEach((row) => {
        const rowCategory = row.getAttribute("data-category");
        if (category === "all" || rowCategory === category) {
          row.style.display = "";
        } else {
          row.style.display = "none";
        }
      });
    });
  });

  // 6. Active TOC Scroll Spy
  const observerOptions = {
    root: null,
    rootMargin: "-80px 0px -70% 0px",
    threshold: 0,
  };

  const headings = document.querySelectorAll("h2[id], h3[id]");
  const tocLinks = document.querySelectorAll(".toc-item a");

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute("id");
        tocLinks.forEach((link) => {
          if (link.getAttribute("href") === `#${id}`) {
            document.querySelectorAll(".toc-item").forEach((it) => it.classList.remove("active"));
            link.parentElement.classList.add("active");
          }
        });
      }
    });
  }, observerOptions);

  headings.forEach((heading) => observer.observe(heading));
});
