import csv
import html
import json
import sys

from huepy import bold, green

from wappalyzer.core.config import cat_db, groups_db, tech_db
from wappalyzer.core.matcher import parse_pattern


def get_cats_and_groups(tech_name):
    cats = []
    groups = []
    for cat in tech_db.get(tech_name, {}).get("cats", []):
        category = cat_db.get(str(cat), {})
        category_name = category.get("name")

        if category_name and category_name not in cats:
            cats.append(category_name)

        for group in category.get("groups", []):
            this_group = groups_db.get(str(group), {}).get("name")

            if not this_group:
                continue

            if this_group not in groups:
                groups.append(this_group)

    return cats, groups


def relationship_names(value):
    values = value if isinstance(value, list) else [value]
    return [parse_pattern(item)[0] for item in values]


def detection_rank(name, detection):
    return (
        detection.get("confidence", 0),
        detection.get("_direct", False),
        bool(detection.get("version")),
        -list(tech_db).index(name) if name in tech_db else 0,
    )


def resolve_implies(detections):
    changed = True

    while changed:
        changed = False

        for source_name in sorted(tuple(detections)):
            source_data = tech_db.get(source_name, {})
            implied_values = source_data.get("implies", [])
            implied_values = (
                implied_values if isinstance(implied_values, list) else [implied_values]
            )

            for implied_value in implied_values:
                implied_name, version, confidence = parse_pattern(implied_value)

                if implied_name not in tech_db:
                    continue

                candidate = {
                    "version": version,
                    "confidence": min(
                        detections[source_name].get("confidence", 100),
                        confidence,
                    ),
                    "_direct": False,
                }

                if implied_name not in detections:
                    detections[implied_name] = candidate
                    changed = True


def resolve_excludes(detections):
    to_remove = set()

    for source_name in sorted(detections):
        source_excludes = relationship_names(tech_db.get(source_name, {}).get("excludes", []))
        for excluded_name in source_excludes:
            if excluded_name not in detections or excluded_name in to_remove:
                continue

            target_excludes = set(
                relationship_names(tech_db.get(excluded_name, {}).get("excludes", []))
            )

            if source_name in target_excludes:
                source_rank = detection_rank(source_name, detections[source_name])
                target_rank = detection_rank(excluded_name, detections[excluded_name])

                if source_rank < target_rank:
                    to_remove.add(source_name)
                elif target_rank < source_rank:
                    to_remove.add(excluded_name)
                else:
                    to_remove.add(max(source_name, excluded_name))
            else:
                to_remove.add(excluded_name)

    for name in to_remove:
        detections.pop(name, None)


def requirements_met(name, detections):
    technology = tech_db.get(name, {})
    required = relationship_names(technology.get("requires", []))
    required_categories = technology.get("requiresCategory", [])
    required_categories = (
        required_categories if isinstance(required_categories, list) else [required_categories]
    )
    gates = []

    if required:
        gates.append(any(item in detections for item in required))

    if required_categories:
        detected_categories = {
            category
            for detected_name in detections
            for category in tech_db.get(detected_name, {}).get("cats", [])
        }
        gates.append(any(category in detected_categories for category in required_categories))

    return not gates or any(gates)


def resolve_requirements(detections):
    admitted = {
        name: value
        for name, value in detections.items()
        if not tech_db.get(name, {}).get("requires")
        and not tech_db.get(name, {}).get("requiresCategory")
    }
    pending = {name: value for name, value in detections.items() if name not in admitted}

    while pending:
        trigger_detections = {name: value.copy() for name, value in admitted.items()}
        resolve_excludes(trigger_detections)
        resolve_implies(trigger_detections)
        newly_admitted = [
            name for name in sorted(pending) if requirements_met(name, trigger_detections)
        ]

        if not newly_admitted:
            break

        for name in newly_admitted:
            admitted[name] = pending.pop(name)

    detections.clear()
    detections.update(admitted)


def enrich_result(detections):
    enriched = {}

    for tech_name in sorted(detections):
        value = detections[tech_name]
        categories, groups = get_cats_and_groups(tech_name)
        enriched[tech_name] = {
            "version": value.get("version", ""),
            "confidence": value.get("confidence", 100),
            "categories": categories,
            "groups": groups,
        }

    return enriched


def create_result(technologies):
    resolved = {}

    for tech_name, value in technologies.items():
        confidence = max(0, min(int(value.get("confidence", 100)), 100))

        if confidence == 0:
            continue

        candidate = {
            "version": value.get("version", ""),
            "confidence": confidence,
            "_direct": True,
        }

        resolved[tech_name] = candidate

    resolve_requirements(resolved)
    resolve_excludes(resolved)
    resolve_implies(resolved)

    return enrich_result(resolved)


def pretty_print(result):
    for url, value in result.items():
        output_string = bold(green(url)) + " "
        for name, data in value.items():
            if data["version"]:
                output_string += f"{name} v{data['version']}, "
            else:
                output_string += f"{name}, "
        print(output_string.rstrip(", "))


def generate_html_report(data):
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>wappalyzer results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .controls {
            margin-bottom: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .search-container {
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }
        .search-wrapper {
            position: relative;
            flex-grow: 1;
        }
        .search-box {
            padding: 8px;
            width: 100%;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        .autocomplete-list {
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-radius: 4px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }
        .autocomplete-item {
            padding: 8px;
            cursor: pointer;
        }
        .autocomplete-item:hover {
            background-color: #f0f0f0;
        }
        .tags-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        .tag {
            background-color: #e0e0e0;
            border-radius: 16px;
            padding: 4px 12px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9em;
        }
        .tag-remove {
            cursor: pointer;
            color: #666;
            font-weight: bold;
        }
        .tag-remove:hover {
            color: #333;
        }
        button {
            padding: 8px 16px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            white-space: nowrap;
        }
        button:hover {
            background-color: #45a049;
        }
        .results {
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 20px;
        }
        .site {
            margin-bottom: 20px;
            display: none;
        }
        .site.visible {
            display: block;
        }
        .site-url {
            font-size: 1.2em;
            color: #2196F3;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .tech-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 10px;
        }
        .tech-item {
            padding: 8px;
            background-color: #f5f5f5;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .tech-name {
            font-weight: bold;
        }
        .tech-meta {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>    
    <div class="controls">
        <div class="search-container">
            <div class="search-wrapper">
                <input type="text" id="searchInput" class="search-box" placeholder="Search technologies or URLs...">
                <div id="autocompleteList" class="autocomplete-list"></div>
            </div>
            <button onclick="downloadUrls()">Download URLs</button>
        </div>
        <div id="tagsContainer" class="tags-container"></div>
    </div>
    
    <div class="results" id="results">
    """

    for url, technologies in data.items():
        safe_url = html.escape(str(url), quote=True)
        html_template += f'''
        <div class="site" data-url="{safe_url.lower()}">
            <div class="site-url">{safe_url}</div>
            <div class="tech-grid">
        '''

        for tech_name, tech_info in technologies.items():
            safe_tech_name = html.escape(str(tech_name), quote=True)
            version = f" v{html.escape(str(tech_info['version']))}" if tech_info["version"] else ""
            categories = html.escape(", ".join(tech_info["categories"]))
            groups = html.escape(", ".join(tech_info["groups"]))

            html_template += f'''
            <div class="tech-item" data-tech="{safe_tech_name.lower()}">
                <div class="tech-name">{safe_tech_name}{version}</div>
                <div class="tech-meta">
                    {categories} | {groups}
                </div>
            </div>
            '''

        html_template += """
            </div>
        </div>
        """

    html_template += """
    </div>

    <script>
        let activeTags = new Set();
        let allTechnologies = new Set();
        
        // Initialize technologies set
        function initializeTechnologies() {
            const techItems = document.getElementsByClassName('tech-item');
            Array.from(techItems).forEach(item => {
                const techName = item.querySelector('.tech-name').textContent.split(' v')[0];
                allTechnologies.add(techName);
            });
        }
        
        // Initial setup - show all sites
        function initializeSites() {
            const sites = document.getElementsByClassName('site');
            Array.from(sites).forEach(site => site.classList.add('visible'));
            initializeTechnologies();
        }
        
        // Autocomplete functionality
        function showAutocomplete(searchTerm) {
            const autocompleteList = document.getElementById('autocompleteList');
            autocompleteList.innerHTML = '';
            
            if (!searchTerm) {
                autocompleteList.style.display = 'none';
                return;
            }
            
            const matches = Array.from(allTechnologies)
                .filter(tech => tech.toLowerCase().includes(searchTerm.toLowerCase()))
                .filter(tech => !activeTags.has(tech));
                
            if (matches.length === 0) {
                autocompleteList.style.display = 'none';
                return;
            }
            
            matches.forEach(tech => {
                const item = document.createElement('div');
                item.className = 'autocomplete-item';
                item.textContent = tech;
                item.onclick = () => addTag(tech);
                autocompleteList.appendChild(item);
            });
            
            autocompleteList.style.display = 'block';
        }
        
        // Add tag
        function addTag(technology) {
            if (activeTags.has(technology)) return;
            
            activeTags.add(technology);
            const tagsContainer = document.getElementById('tagsContainer');
            
            const tag = document.createElement('div');
            tag.className = 'tag';
            tag.appendChild(document.createTextNode(technology));
            const removeButton = document.createElement('span');
            removeButton.className = 'tag-remove';
            removeButton.textContent = '×';
            removeButton.onclick = () => removeTag(technology);
            tag.appendChild(removeButton);
            
            tagsContainer.appendChild(tag);
            document.getElementById('searchInput').value = '';
            document.getElementById('autocompleteList').style.display = 'none';
            updateResults();
        }
        
        // Remove tag
        function removeTag(technology) {
            activeTags.delete(technology);
            const tagsContainer = document.getElementById('tagsContainer');
            const tags = tagsContainer.getElementsByClassName('tag');
            
            Array.from(tags).forEach(tag => {
                if (tag.textContent.trim().includes(technology)) {
                    tag.remove();
                }
            });
            
            updateResults();
        }
        
        // Update results based on active tags
        function updateResults() {
            const sites = document.getElementsByClassName('site');
            
            Array.from(sites).forEach(site => {
                const techItems = site.getElementsByClassName('tech-item');
                let hasAllTags = true;
                
                if (activeTags.size === 0) {
                    site.classList.add('visible');
                    return;
                }
                
                for (let tag of activeTags) {
                    let hasTag = false;
                    Array.from(techItems).forEach(item => {
                        const techName = item.querySelector('.tech-name').textContent.split(' v')[0];
                        if (techName === tag) {
                            hasTag = true;
                        }
                    });
                    if (!hasTag) {
                        hasAllTags = false;
                        break;
                    }
                }
                
                if (hasAllTags) {
                    site.classList.add('visible');
                } else {
                    site.classList.remove('visible');
                }
            });
        }
        
        // Search input event handlers
        document.getElementById('searchInput').addEventListener('input', function(e) {
            showAutocomplete(e.target.value);
        });
        
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.search-wrapper')) {
                document.getElementById('autocompleteList').style.display = 'none';
            }
        });

        // Download URLs functionality
        function downloadUrls() {
            const visibleSites = Array.from(document.getElementsByClassName('site'))
                .filter(site => site.classList.contains('visible'));
            
            let urls = visibleSites.map(site => site.getAttribute('data-url'));
            let content = urls.join('\\n');
            
            const blob = new Blob([content], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.setAttribute('href', url);
            a.setAttribute('download', 'matched_urls.txt');
            a.click();
        }
        
        // Initialize on page load
        initializeSites();
    </script>
</body>
</html>
    """

    return html_template


def write_to_file(filepath, data, format="json"):
    if format == "json":
        if filepath == "-":
            json.dump(data, sys.stdout)
            sys.stdout.write("\n")
        else:
            with open(filepath, "w+") as f:
                json.dump(data, f)
    elif format == "csv":
        output = sys.stdout if filepath == "-" else open(filepath, "w+", newline="")
        try:
            writer = csv.writer(output)
            for url, technologies in data.items():
                for tech, tech_data in technologies.items():
                    writer.writerow(
                        [
                            url,
                            tech,
                            tech_data["version"],
                            tech_data["confidence"],
                            " ".join(tech_data["categories"]),
                            " ".join(tech_data["groups"]),
                        ]
                    )
        finally:
            if filepath != "-":
                output.close()
    elif format == "html":
        html_content = generate_html_report(data)
        if filepath == "-":
            sys.stdout.write(html_content)
            sys.stdout.write("\n")
        else:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)
