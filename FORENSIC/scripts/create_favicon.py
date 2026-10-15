#!/usr/bin/env python3
"""Create a custom favicon that matches the EVI forensic theme."""

from PIL import Image, ImageDraw
import os

def create_favicon():
    """Create a forensic-themed favicon."""
    static_dir = os.path.join('FORENSIC', 'static')
    
    # Colors matching the app theme
    dark_bg = (10, 14, 39)  # Dark blue background
    accent_blue = (59, 130, 246)  # #3b82f6 - primary accent
    light_blue = (99, 102, 241)  # #6366f1 - secondary accent
    white = (255, 255, 255)
    
    def create_favicon_image(size):
        """Create a favicon image at the specified size."""
        # Create image with transparent background
        img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw circular background with gradient effect
        margin = size // 8
        bg_size = size - (margin * 2)
        
        # Outer circle (dark blue)
        draw.ellipse([margin, margin, size - margin, size - margin], 
                    fill=dark_bg + (255,), outline=accent_blue + (200,), width=max(1, size // 32))
        
        # Inner circle (lighter blue gradient effect)
        inner_margin = margin + bg_size // 6
        inner_size = size - (inner_margin * 2)
        draw.ellipse([inner_margin, inner_margin, size - inner_margin, size - inner_margin], 
                    fill=accent_blue + (180,))
        
        # Draw a stylized fingerprint pattern or "E" for EVI
        center = size // 2
        
        if size >= 32:
            # For larger sizes, draw a stylized "E" with forensic elements
            # Draw the letter "E"
            stroke_width = max(2, size // 16)
            e_width = size // 3
            e_height = size // 2
            e_x = center - e_width // 2
            e_y = center - e_height // 2
            
            # Vertical line of E
            draw.line([e_x, e_y, e_x, e_y + e_height], 
                     fill=white + (255,), width=stroke_width)
            # Top horizontal line
            draw.line([e_x, e_y, e_x + e_width, e_y], 
                     fill=white + (255,), width=stroke_width)
            # Middle horizontal line
            draw.line([e_x, e_y + e_height // 2, e_x + e_width * 3 // 4, e_y + e_height // 2], 
                     fill=white + (255,), width=stroke_width)
            # Bottom horizontal line
            draw.line([e_x, e_y + e_height, e_x + e_width, e_y + e_height], 
                     fill=white + (255,), width=stroke_width)
            
            # Add small accent dots (representing digital/forensic elements)
            dot_size = max(1, size // 20)
            dots = [
                (e_x + e_width + size // 12, e_y + size // 6),
                (e_x + e_width + size // 12, e_y + e_height - size // 6),
            ]
            for dot_x, dot_y in dots:
                draw.ellipse([dot_x - dot_size, dot_y - dot_size, 
                             dot_x + dot_size, dot_y + dot_size], 
                            fill=accent_blue + (255,))
        else:
            # For very small sizes (16x16), just draw a simple "E"
            stroke_width = 1
            e_width = size // 2
            e_height = size // 2
            e_x = center - e_width // 2
            e_y = center - e_height // 2
            
            # Simplified E for small size
            draw.line([e_x, e_y, e_x, e_y + e_height], fill=white + (255,), width=stroke_width)
            draw.line([e_x, e_y, e_x + e_width, e_y], fill=white + (255,), width=stroke_width)
            draw.line([e_x, e_y + e_height // 2, e_x + e_width * 2 // 3, e_y + e_height // 2], 
                     fill=white + (255,), width=stroke_width)
            draw.line([e_x, e_y + e_height, e_x + e_width, e_y + e_height], 
                     fill=white + (255,), width=stroke_width)
        
        return img
    
    # Create favicons in standard sizes
    sizes = {
        'favicon-16x16.png': 16,
        'favicon-32x32.png': 32,
        'apple-touch-icon.png': 180,
    }
    
    for filename, size in sizes.items():
        output_path = os.path.join(static_dir, filename)
        img = create_favicon_image(size)
        img.save(output_path, 'PNG')
        print(f"Created: {filename} ({size}x{size})")
    
    # Also create a 64x64 version for general use
    img_64 = create_favicon_image(64)
    img_64.save(os.path.join(static_dir, 'logo-1.png'), 'PNG')
    print(f"Created: logo-1.png (64x64)")
    
    print("\n✅ Custom favicon creation complete!")
    print("Theme: Dark forensic blue with white 'E' for EVI")

if __name__ == '__main__':
    # Get the script directory and navigate to project root
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    os.chdir(project_root)
    create_favicon()

