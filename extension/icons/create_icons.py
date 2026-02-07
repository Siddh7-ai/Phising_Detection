from PIL import Image, ImageDraw, ImageFont
import os

# Create simple shield icons
sizes = [16, 48, 128]

for size in sizes:
    # Create image with transparent background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Draw shield shape (simple)
    padding = size // 8
    shield_color = (102, 126, 234, 255)  # Purple
    
    # Shield outline
    points = [
        (size//2, padding),  # Top center
        (size - padding, padding + size//4),  # Right top
        (size - padding, size - padding*2),  # Right bottom
        (size//2, size - padding),  # Bottom center
        (padding, size - padding*2),  # Left bottom
        (padding, padding + size//4),  # Left top
    ]
    
    draw.polygon(points, fill=shield_color, outline=(70, 90, 200, 255))
    
    # Save
    img.save(f'icon{size}.png')
    print(f'Created icon{size}.png')

print('Icons created successfully!')
