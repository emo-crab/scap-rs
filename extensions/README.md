# Mark CVE
---
[![github]](https://github.com/emo-crab/scap-rs/tree/main/extensions)

[github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github

- Mark the current page CVE.

## Using

- Install the plugin, open a webpage with a CVE number, click on the plugin, and you will see a button added after the CVE.

![](assets/Screenshot AttackerKB.png)

## Bookmark JavaScript
- Create a bookmark, Edit the `URL` as the following script.
```javascript
javascript: (function () {
    function Mark() {
        const userSelection = window.getSelection();
        const id = userSelection.toString();
        let cve = userSelection.getRangeAt(0).startContainer.parentNode;
        if (cve.getElementsByClassName("Marked").length > 0) {
            return;
        }
        const spanElement = document.createElement("span");
        spanElement.setAttribute("class", "Marked");
        const selectedTextRange = userSelection.getRangeAt(0);
        selectedTextRange.surroundContents(spanElement);
        const icon = document.createElement("a");
        icon.href = "https://scap.kali-team.cn/cve/" + id;
        icon.target = "_blank";
        const svg = document.createElement('img');
        svg.setAttribute("style", "background-color: rgb(154, 205, 50);");
        svg.src = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIGNsYXNzPSJpY29uIGljb24tdGFibGVyIGljb24tdGFibGVyLWJ1ZyIgd2lkdGg9IjI0IiBoZWlnaHQ9IjI0IiB2aWV3Qm94PSIwIDAgMjQgMjQiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIGZpbGw9Im5vbmUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIgc3Ryb2tlLWxpbmVqb2luPSJyb3VuZCI+PHBhdGggc3Ryb2tlPSJub25lIiBkPSJNMCAwaDI0djI0SDB6IiBmaWxsPSJub25lIi8+PHBhdGggZD0iTTkgOXYtMWEzIDMgMCAwIDEgNiAwdjEiIC8+PHBhdGggZD0iTTggOWg4YTYgNiAwIDAgMSAxIDN2M2E1IDUgMCAwIDEgLTEwIDB2LTNhNiA2IDAgMCAxIDEgLTMiIC8+PHBhdGggZD0iTTMgMTNsNCAwIiAvPjxwYXRoIGQ9Ik0xNyAxM2w0IDAiIC8+PHBhdGggZD0iTTEyIDIwbDAgLTYiIC8+PHBhdGggZD0iTTQgMTlsMy4zNSAtMiIgLz48cGF0aCBkPSJNMjAgMTlsLTMuMzUgLTIiIC8+PHBhdGggZD0iTTQgN2wzLjc1IDIuNCIgLz48cGF0aCBkPSJNMjAgN2wtMy43NSAyLjQiIC8+PC9zdmc+";
        icon.appendChild(svg);
        spanElement.appendChild(icon);
    }

    function FindCVE() {
        const regex = new RegExp('\\bCVE-\\d{4}-\\d{4,7}\\b', 'gmi');
        document.designMode = "on";
        const sel = window.getSelection();
        sel.collapse(document.body, 0);
        let m;
        while (m = regex.exec(document.body.innerText)) {
            while (window.find(m)) {
                Mark();
            }
        }
        document.designMode = "off";
    }

    FindCVE();
})();

```