#!/usr/bin/env python3
"""Resize logo-1.png to standard favicon sizes."""

from PIL import Image
import os

def resize_favicon():
    """Resize logo-1.png to standard favicon sizes."""
    # Get the script directory and navigate to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    input_path = os.path.join(project_root, 'FORENSIC', 'static', 'logo-1.png')
    static_dir = os.path.join(project_root, 'FORENSIC', 'static')
    
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found")
        return
    
    # Open the original image
    img = Image.open(input_path)
    print(f"Original size: {img.size[0]}x{img.size[1]}")
    
    # Convert to RGBA if not already (for transparency support)
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Standard favicon sizes
    sizes = {
        'favicon-16x16.png': (16, 16),
        'favicon-32x32.png': (32, 32),
        'favicon.ico': (32, 32),  # ICO format, but we'll save as PNG
        'apple-touch-icon.png': (180, 180),
        'logo-1.png': (64, 64)  # Keep a medium size for general use
    }
    
    for filename, size in sizes.items():
        output_path = os.path.join(static_dir, filename)
        resized = img.resize(size, Image.Resampling.LANCZOS)
        
        if filename == 'favicon.ico':
            # For ICO, we'll create a 32x32 PNG and rename it
            # Actually, let's just create a 32x32 PNG for favicon.ico
            resized.save(output_path.replace('.ico', '.png'), 'PNG')
            print(f"Created: {filename.replace('.ico', '.png')} ({size[0]}x{size[1]})")
        else:
            resized.save(output_path, 'PNG')
            print(f"Created: {filename} ({size[0]}x{size[1]})")
    
    print("\nFavicon resizing complete!")

if __name__ == '__main__':
    resize_favicon()

