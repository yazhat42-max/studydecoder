"""
Convert all PDF past papers to text files for use by the AI practice question generator.
Outputs to api/syllabuses/past-papers/ directory.
"""
import os
import PyPDF2
import shutil

SOURCE_DIR = r"c:\Users\Yazan\OneDrive\Documents\past-papers"
DEST_DIR = r"c:\Users\Yazan\OneDrive\Documents\website\api\syllabuses\past-papers"

# Create destination directory
os.makedirs(DEST_DIR, exist_ok=True)

converted = 0
copied = 0
errors = []

for filename in sorted(os.listdir(SOURCE_DIR)):
    src_path = os.path.join(SOURCE_DIR, filename)
    
    if filename.endswith('.pdf'):
        # Convert PDF to text
        txt_filename = filename.replace('.pdf', '.txt')
        dest_path = os.path.join(DEST_DIR, txt_filename)
        
        try:
            reader = PyPDF2.PdfReader(src_path)
            text = ""
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n\n"
            
            with open(dest_path, 'w', encoding='utf-8') as f:
                f.write(text)
            
            converted += 1
            print(f"✅ Converted: {filename} -> {txt_filename} ({len(text)} chars)")
        except Exception as e:
            errors.append((filename, str(e)))
            print(f"❌ Error converting {filename}: {e}")
    
    elif filename.endswith('.txt'):
        # Copy text files directly
        dest_path = os.path.join(DEST_DIR, filename)
        shutil.copy2(src_path, dest_path)
        copied += 1
        print(f"📋 Copied: {filename}")

print(f"\n{'='*60}")
print(f"Summary: {converted} PDFs converted, {copied} text files copied")
if errors:
    print(f"Errors ({len(errors)}):")
    for fn, err in errors:
        print(f"  - {fn}: {err}")
print(f"Output directory: {DEST_DIR}")
