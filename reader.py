import fitz # PyMuPDF
import docx
import pandas as pd
import json
import streamlit as st
from PIL import Image
import io

def display_file_content(file_bytes, extension):
    """
    Phase 6: Safe files content display
    """
    ext = extension.lower()
    
    try:
        # TXT / MD / LOG
        if ext in ['.txt', '.md', '.log']:
            text = file_bytes.decode('utf-8', errors='ignore')
            st.code(text, language="markdown" if ext == ".md" else "text")
            
        # CSV
        elif ext == '.csv':
            df = pd.read_csv(io.BytesIO(file_bytes))
            st.dataframe(df)
            st.write("### Data Statistics")
            st.write(df.describe())
            
        # JSON
        elif ext == '.json':
            data = json.loads(file_bytes.decode('utf-8'))
            st.json(data)
            
        # PDF
        elif ext == '.pdf':
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            text = ""
            for i, page in enumerate(doc):
                text += page.get_text()
            st.write("### PDF Metadata")
            st.write(doc.metadata)
            
            st.write("### Content Preview")
            # PDF text with search capability mock layout using text_area
            st.text_area("Extracted Text", text, height=300)
            
        # IMAGES
        elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            img = Image.open(io.BytesIO(file_bytes))
            st.image(img, caption=f"Image Preview (Size: {img.size})")
            try:
                exif = img.getexif()
                if exif:
                    st.write("### EXIF Data")
                    st.write(dict(exif))
            except Exception:
                pass
                
        # HTML / XML
        elif ext in ['.html', '.xml']:
            text = file_bytes.decode('utf-8', errors='ignore')
            st.write("### Source Code")
            st.code(text[:2000] + ("..." if len(text)>2000 else ""), language="html" if ext == '.html' else "xml")
            if ext == '.html':
                st.write("### Rendered Preview")
                st.components.v1.html(text, height=400, scrolling=True)
                
        # DOCX
        elif ext == '.docx':
            doc = docx.Document(io.BytesIO(file_bytes))
            text = "\n".join([para.text for para in doc.paragraphs])
            st.text_area("Word Document Content", text, height=300)
            
        else:
            st.info(f"Reader format preview not mapped for: {ext}")
            
    except Exception as e:
        st.error(f"Error parsing and reading file content: {str(e)}")
