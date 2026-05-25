/* ============================================================
   Study Decoder — shared subject + module catalog
   Single source of truth for subject IDs, display names, and the
   real module/topic list per subject (senior HSC + junior 7-10).
   Mirrors the data the Worksheet Generator uses so every tool shows
   the same known modules.
   Exposes window.SD_SUBJECTS with helpers.
   ============================================================ */
(function () {
  const SUBJECTS_SENIOR = [
    { id: 'agriculture', name: 'Agriculture', category: 'TAS' },
    { id: 'ancient-history', name: 'Ancient History', category: 'HSIE' },
    { id: 'biology', name: 'Biology', category: 'Science' },
    { id: 'business-studies', name: 'Business Studies', category: 'HSIE' },
    { id: 'chemistry', name: 'Chemistry', category: 'Science' },
    { id: 'construction', name: 'Construction', category: 'VET' },
    { id: 'dance', name: 'Dance', category: 'Creative Arts' },
    { id: 'design-technology', name: 'Design and Technology', category: 'TAS' },
    { id: 'drama', name: 'Drama', category: 'Creative Arts' },
    { id: 'earth-environmental-science', name: 'Earth and Environmental Science', category: 'Science' },
    { id: 'economics', name: 'Economics', category: 'HSIE' },
    { id: 'engineering-studies', name: 'Engineering Studies', category: 'TAS' },
    { id: 'english-advanced', name: 'English Advanced', category: 'English' },
    { id: 'english-eald', name: 'English EAL/D', category: 'English' },
    { id: 'english-extension', name: 'English Extension', category: 'English' },
    { id: 'english-standard', name: 'English Standard', category: 'English' },
    { id: 'english-studies', name: 'English Studies', category: 'English' },
    { id: 'enterprise-computing', name: 'Enterprise Computing', category: 'TAS' },
    { id: 'food-technology', name: 'Food Technology', category: 'TAS' },
    { id: 'geography', name: 'Geography', category: 'HSIE' },
    { id: 'health-movement-science', name: 'Health and Movement Science', category: 'PDHPE' },
    { id: 'history-extension', name: 'History Extension', category: 'HSIE' },
    { id: 'hospitality', name: 'Hospitality', category: 'VET' },
    { id: 'industrial-tech-automotive', name: 'Industrial Technology - Automotive', category: 'TAS' },
    { id: 'industrial-tech-electronics', name: 'Industrial Technology - Electronics', category: 'TAS' },
    { id: 'industrial-tech-graphics', name: 'Industrial Technology - Graphics', category: 'TAS' },
    { id: 'industrial-tech-metals', name: 'Industrial Technology - Metal and Engineering', category: 'TAS' },
    { id: 'industrial-tech-multimedia', name: 'Industrial Technology - Multimedia', category: 'TAS' },
    { id: 'industrial-tech-timber', name: 'Industrial Technology - Timber and Furniture', category: 'TAS' },
    { id: 'information-digital-technology', name: 'Information and Digital Technology', category: 'TAS' },
    { id: 'investigating-science', name: 'Investigating Science', category: 'Science' },
    { id: 'legal-studies', name: 'Legal Studies', category: 'HSIE' },
    { id: 'mathematics-advanced', name: 'Mathematics Advanced', category: 'Mathematics' },
    { id: 'mathematics-extension-1', name: 'Mathematics Extension 1', category: 'Mathematics' },
    { id: 'mathematics-extension-2', name: 'Mathematics Extension 2', category: 'Mathematics' },
    { id: 'mathematics-standard', name: 'Mathematics Standard', category: 'Mathematics' },
    { id: 'modern-history', name: 'Modern History', category: 'HSIE' },
    { id: 'music-1', name: 'Music 1', category: 'Creative Arts' },
    { id: 'music-2', name: 'Music 2', category: 'Creative Arts' },
    { id: 'physics', name: 'Physics', category: 'Science' },
    { id: 'science-extension', name: 'Science Extension', category: 'Science' },
    { id: 'society-culture', name: 'Society and Culture', category: 'HSIE' },
    { id: 'software-engineering', name: 'Software Engineering', category: 'TAS' },
    { id: 'studies-of-religion', name: 'Studies of Religion', category: 'HSIE' },
    { id: 'visual-arts', name: 'Visual Arts', category: 'Creative Arts' }
  ];
  const SUBJECTS_JUNIOR = [
    { id: 'english-7-10', name: 'English (Years 7-10)', category: 'English' },
    { id: 'mathematics-7-10', name: 'Mathematics (Years 7-10)', category: 'Mathematics' },
    { id: 'science-7-10', name: 'Science (Years 7-10)', category: 'Science' }
  ];

  const TOPICS_SENIOR = {
    'agriculture': ['Farm case study','Plant production','Animal production','Plant/Animal production','Farm product study','Electives (Agri-food, Fibre and Fuel Technologies / Climate Challenge / Farming for the 21st Century)'],
    'ancient-history': ['Investigating Ancient History','Features of Ancient Societies','Historical Investigation','Core Study: Cities of Vesuvius - Pompeii and Herculaneum','Ancient Societies','Personalities in Their Times','Historical Periods'],
    'biology': ['Module 1: Cells as the Basis of Life','Module 2: Organisation of Living Things','Module 3: Biological Diversity','Module 4: Ecosystem Dynamics','Module 5: Heredity','Module 6: Genetic Change','Module 7: Infectious Disease','Module 8: Non-infectious Disease and Disorders'],
    'business-studies': ['Nature of business','Business management','Business planning','Operations','Marketing','Finance','Human resources'],
    'chemistry': ['Module 1: Properties and Structure of Matter','Module 2: Introduction to Quantitative Chemistry','Module 3: Reactive Chemistry','Module 4: Drivers of Reactions','Module 5: Equilibrium and Acid Reactions','Module 6: Acid/Base Reactions','Module 7: Organic Chemistry','Module 8: Applying Chemical Ideas'],
    'construction': ['Safety','Skills in construction','Tools of the trade','Working in the industry'],
    'dance': ['Performance','Composition','Appreciation','Core Performance','Core Composition','Core Appreciation','Major Study'],
    'design-technology': ['Designing and Producing','Innovation and Emerging Technologies','Project proposal and development','Project realisation','Project evaluation'],
    'drama': ['Improvisation, Playbuilding and Acting','Elements of Production in Performance','Theatrical Traditions and Performance Styles','Australian Drama and Theatre (Core)','Studies in Drama and Theatre','Group Performance','Individual Project'],
    'earth-environmental-science': ['Module 1: Earth\'s Resources','Module 2: Plate Tectonics','Module 3: Energy Transformations','Module 4: Human Impacts','Module 5: Earth\'s Processes','Module 6: Hazards','Module 7: Climate Science','Module 8: Resource Management'],
    'economics': ['Introduction to Economics','Consumers and Business','Markets','Labour Markets','Financial Markets','Government and the Economy','The Global Economy','Australia\'s Place in the Global Economy','Economic Issues','Economic Policies and Management'],
    'engineering-studies': ['Engineering Fundamentals','Engineered Products','Braking Systems','Biomedical Engineering','Civil Structures','Personal and Public Transport','Aeronautical Engineering','Telecommunications Engineering'],
    'english-advanced': ['Texts and human experiences','Textual conversations','Critical study of literature','Narratives that shape our world','The craft of writing'],
    'english-eald': ['Texts and human experiences','Language, identity and culture','Close study of text','Texts and society','Writing'],
    'english-extension': ['Texts, culture and value','Related research project','Literary worlds (Extension 1)','Author and authority (Extension 2)','Major work (Extension 2)'],
    'english-standard': ['Texts and human experiences','Language, identity and culture','Close study of literature','Contemporary possibilities','The craft of writing'],
    'english-studies': ['Texts and human experiences','Achieving through English','Writing for purpose','Module options'],
    'enterprise-computing': ['Interactive Media and the User Experience','Networking Systems and Social Computing','Principles of Cybersecurity','Data Science','Data Visualisation','Intelligent Systems','Enterprise Project'],
    'food-technology': ['Food Availability and Selection','Food Quality','Nutrition','The Australian Food Industry','Food Manufacture','Food Product Development','Contemporary Nutrition Issues'],
    'geography': ['Ecosystems and global biodiversity','Rural and urban places','People, patterns and processes','Human-environment interactions','Global sustainability','Geographical Investigation'],
    'health-movement-science': ['Health for individuals and communities','The body and mind in motion','Collaborative Investigation','Health in an Australian and global context','Training for improved performance'],
    'history-extension': ['Specialised Historical Studies','Research Project'],
    'hospitality': ['Hospitality Operations','Food and Beverage Services','Hospitality and Tourism','Hospitality Businesses','Hospitality Services'],
    'industrial-tech-automotive': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'industrial-tech-electronics': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'industrial-tech-graphics': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'industrial-tech-metals': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'industrial-tech-multimedia': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'industrial-tech-timber': ['Industry Study','Design, Management and Communication','Production','Industry Related Manufacturing Technology'],
    'information-digital-technology': ['Information Systems','Digital Systems','Data and Information','Networking and Cloud Computing','Digital Issues and Implications'],
    'investigating-science': ['Module 1: Cause and Effect - Observing','Module 2: Cause and Effect - Inferences and Generalisations','Module 3: Scientific Models','Module 4: Theories and Laws','Module 5: Scientific Investigations','Module 6: Technologies','Module 7: Fact or Fallacy?','Module 8: Science and Society'],
    'legal-studies': ['The Legal System','The Individual and the Law','Law in Practice','Crime','Human Rights','Options'],
    'mathematics-advanced': ['Functions','Trigonometric Functions','Calculus','Exponential and Logarithmic Functions','Statistical Analysis','Financial Mathematics'],
    'mathematics-extension-1': ['Functions','Trigonometric Functions','Calculus','Combinatorics','Proof','Vectors','Statistical Analysis'],
    'mathematics-extension-2': ['Proof','Vectors','Complex Numbers','Calculus','Mechanics'],
    'mathematics-standard': ['Algebra','Measurement','Financial Mathematics','Statistical Analysis','Networks','Probability'],
    'modern-history': ['Core Study: Power and Authority in the Modern World 1919-1946','National Studies','Peace and Conflict','Change in the Modern World'],
    'music-1': ['Performance','Composition','Musicology','Aural Skills'],
    'music-2': ['Performance','Composition','Musicology','Aural Skills','Music 1600-1900','Music of the Last 25 Years'],
    'physics': ['Module 1: Kinematics','Module 2: Dynamics','Module 3: Waves and Thermodynamics','Module 4: Electricity and Magnetism','Module 5: Advanced Mechanics','Module 6: Electromagnetism','Module 7: The Nature of Light','Module 8: From the Universe to the Atom'],
    'science-extension': ['Science Inquiry and Innovation Project'],
    'society-culture': ['The Social and Cultural World','Personal and Social Identity','Intercultural Communication','Social and Cultural Continuity and Change (Core)','Personal Interest Project (PIP)','Depth Studies'],
    'software-engineering': ['Programming Fundamentals','The Object-Oriented Paradigm','Programming Mechatronics','Secure Software Architecture','Programming for the Web','Software Automation','Software Engineering Project'],
    'studies-of-religion': ['Nature of Religion and Beliefs','Religious Tradition Studies','Religion and Belief Systems in Australia post-1945','Religion and Peace','Religion and Non-Religion','Religions of Ancient Origin'],
    'visual-arts': ['Artmaking Practice','Art Criticism and Art History','The Conceptual Framework','The Frames','Body of Work Development','Case Studies']
  };
  const TOPICS_JUNIOR = {
    'english-7-10': ['Reading and Comprehension','Creative Writing','Persuasive Writing','Essay Writing','Poetry Analysis','Novel Study','Film Study','Grammar and Punctuation','Speaking and Listening','Visual Texts','Drama and Performance Texts'],
    'mathematics-7-10': ['Integers and Whole Numbers','Fractions, Decimals and Percentages','Ratios and Rates','Algebra - Expressions','Algebra - Equations','Linear Relationships','Coordinate Geometry','Indices and Surds','Measurement - Length, Area and Volume','Geometry - Angles and Polygons','Statistics and Data Analysis','Probability','Trigonometry','Pythagoras Theorem','Quadratic Expressions and Equations','Financial Mathematics'],
    'science-7-10': ['Cells and Living Things','Body Systems','Reproduction and Inheritance','Ecosystems and Food Webs','Classification of Living Things','Forces and Motion','Energy and Energy Transfers','Waves, Light and Sound','Electricity and Magnetism','Elements, Compounds and Mixtures','Chemical Reactions','Atoms and the Periodic Table','Acids and Bases','Earth Systems and Climate','Space and the Universe','Working Scientifically']
  };

  const ALL_SUBJECTS = SUBJECTS_SENIOR.concat(SUBJECTS_JUNIOR);
  const ALL_TOPICS = Object.assign({}, TOPICS_SENIOR, TOPICS_JUNIOR);
  const ID_TO_NAME = {};
  const NAME_TO_ID = {};
  ALL_SUBJECTS.forEach(s => { ID_TO_NAME[s.id] = s.name; NAME_TO_ID[s.name.toLowerCase()] = s.id; });

  // Common free-text aliases → canonical id (for legacy classes typed by hand).
  const ALIASES = {
    'maths': 'mathematics-advanced', 'math': 'mathematics-advanced',
    'maths advanced': 'mathematics-advanced', 'maths standard': 'mathematics-standard',
    'maths extension 1': 'mathematics-extension-1', 'maths extension 2': 'mathematics-extension-2',
    'bio': 'biology', 'chem': 'chemistry', 'phys': 'physics',
    'eng': 'english-advanced', 'english': 'english-advanced',
    'mod hist': 'modern-history', 'history': 'modern-history',
    'ancient hist': 'ancient-history', 'biz': 'business-studies', 'business': 'business-studies'
  };

  // Resolve any subject reference (id, display name, or loose free text) to a
  // canonical subject id, or null if unknown.
  function resolveId(ref) {
    if (!ref) return null;
    const raw = String(ref).trim();
    if (ALL_TOPICS[raw] || ID_TO_NAME[raw]) return raw;        // already an id
    const lc = raw.toLowerCase();
    if (NAME_TO_ID[lc]) return NAME_TO_ID[lc];                  // exact name
    if (ALIASES[lc]) return ALIASES[lc];                       // alias
    // Loose: a stored name/id that contains or is contained by a known one.
    const hit = ALL_SUBJECTS.find(s =>
      s.id.toLowerCase() === lc || s.name.toLowerCase() === lc ||
      (lc.length >= 4 && (s.name.toLowerCase().includes(lc) || lc.includes(s.name.toLowerCase()))));
    return hit ? hit.id : null;
  }

  function displayName(ref) {
    const id = resolveId(ref);
    return (id && ID_TO_NAME[id]) || String(ref || '');
  }

  // Modules/topics for a subject reference. Returns [] only if truly unknown.
  function modulesFor(ref) {
    const id = resolveId(ref);
    return (id && ALL_TOPICS[id]) ? ALL_TOPICS[id].slice() : [];
  }

  function subjectsForLevel(level) {
    return level === 'junior' ? SUBJECTS_JUNIOR.slice() : SUBJECTS_SENIOR.slice();
  }

  // Faculty display order for grouping subjects in dropdowns.
  const FACULTY_ORDER = ['Mathematics', 'English', 'Science', 'HSIE', 'Creative Arts', 'PDHPE', 'TAS', 'VET'];

  // Subjects for a level grouped by faculty, in a sensible faculty order and
  // alphabetised within each faculty.
  function groupedForLevel(level) {
    const groups = {};
    subjectsForLevel(level).forEach(s => {
      const cat = s.category || 'Other';
      (groups[cat] = groups[cat] || []).push(s);
    });
    const order = FACULTY_ORDER.filter(c => groups[c]).concat(
      Object.keys(groups).filter(c => FACULTY_ORDER.indexOf(c) === -1).sort()
    );
    return order.map(cat => ({
      category: cat,
      subjects: groups[cat].slice().sort((a, b) => a.name.localeCompare(b.name))
    }));
  }

  // Populate a <select> with every subject for the level, grouped into
  // <optgroup> by faculty. Options carry the canonical id as value (or the
  // display name when opts.useName is set, for tools keyed on names).
  // The student's saved subjects (names), for the "⭐ Your Subjects" group.
  // Prefers the live global (set by app-shell after auth), falls back to the
  // cached user record so the group shows on first paint too.
  function getSavedSubjects() {
    try { if (typeof window !== 'undefined' && Array.isArray(window.SD_MY_SUBJECTS)) return window.SD_MY_SUBJECTS; } catch (e) {}
    try {
      var c = JSON.parse(localStorage.getItem('sd_user_cache') || 'null');
      return (c && c.preferences && Array.isArray(c.preferences.subjects)) ? c.preferences.subjects : [];
    } catch (e) { return []; }
  }
  function savedSubjectsForLevel(level) {
    var names = getSavedSubjects();
    if (!names.length) return [];
    var list = subjectsForLevel(level);
    var out = [];
    names.forEach(function (n) {
      var id = resolveId(n);
      var s = list.find(function (x) { return x.id === id; });
      if (s && !out.some(function (o) { return o.id === s.id; })) out.push(s);
    });
    return out;
  }

  function fillSubjectSelect(sel, level, opts) {
    opts = opts || {};
    if (!sel) return;
    const useName = !!opts.useName;
    let html = '';
    if (opts.placeholder !== false) {
      html += '<option value="">' + (opts.placeholder || 'Select your subject…') + '</option>';
    }
    // "⭐ Your Subjects" pinned at the top — consistent across every dropdown.
    if (opts.yourSubjects !== false) {
      const mine = savedSubjectsForLevel(level);
      if (mine.length) {
        html += '<optgroup label="⭐ Your Subjects">';
        mine.forEach(s => {
          const val = useName ? s.name : s.id;
          html += '<option value="' + val + '">' + s.name + '</option>';
        });
        html += '</optgroup>';
      }
    }
    groupedForLevel(level).forEach(g => {
      html += '<optgroup label="' + g.category + '">';
      g.subjects.forEach(s => {
        const val = useName ? s.name : s.id;
        html += '<option value="' + val + '">' + s.name + '</option>';
      });
      html += '</optgroup>';
    });
    sel.innerHTML = html;
  }

  window.SD_SUBJECTS = {
    senior: SUBJECTS_SENIOR,
    junior: SUBJECTS_JUNIOR,
    topics: ALL_TOPICS,
    resolveId, displayName, modulesFor, subjectsForLevel,
    groupedForLevel, fillSubjectSelect
  };
})();
