from PIL import Image, ImageDraw, ImageFont

# Create image with white background
width, height = 800, 600
img = Image.new('RGB', (width, height), color='white')
draw = ImageDraw.Draw(img, 'RGBA')

# Colors from the image
dark_green = (67, 140, 77)
light_green = (152, 207, 113)
dark_blue = (25, 60, 130)
teal = (64, 180, 222)
light_teal = (107, 211, 237)
white = (255, 255, 255)

# Brain-circuit logo position
logo_center_x = width // 2
logo_center_y = height // 2 - 80

# Main brain shapes - left (green)
# Left top lobe
draw.ellipse([logo_center_x - 130, logo_center_y - 100, logo_center_x - 60, logo_center_y - 20], 
             fill=dark_green)

# Left bottom lobe
draw.ellipse([logo_center_x - 140, logo_center_y, logo_center_x - 50, logo_center_y + 90], 
             fill=light_green)

# Right top lobe (teal)
draw.ellipse([logo_center_x + 60, logo_center_y - 100, logo_center_x + 130, logo_center_y - 20], 
             fill=teal)

# Right bottom lobe (darker teal)
draw.ellipse([logo_center_x + 50, logo_center_y, logo_center_x + 140, logo_center_y + 90], 
             fill=dark_blue)

# Center spine/circuit board
draw.rectangle([logo_center_x - 15, logo_center_y - 90, logo_center_x + 15, logo_center_y + 80], 
               fill=white)

# Circuit nodes and connections on left side
# Top left nodes
draw.ellipse([logo_center_x - 120, logo_center_y - 70, logo_center_x - 95, logo_center_y - 45], 
             fill=white, outline=dark_green, width=3)
draw.ellipse([logo_center_x - 105, logo_center_y - 50, logo_center_x - 75, logo_center_y - 20], 
             fill=white, outline=dark_green, width=3)

# Bottom left nodes
draw.ellipse([logo_center_x - 125, logo_center_y + 15, logo_center_x - 100, logo_center_y + 40], 
             fill=white, outline=dark_green, width=3)
draw.ellipse([logo_center_x - 90, logo_center_y + 35, logo_center_x - 65, logo_center_y + 60], 
             fill=white, outline=dark_green, width=3)

# Circuit nodes and connections on right side
# Top right nodes
draw.ellipse([logo_center_x + 95, logo_center_y - 70, logo_center_x + 120, logo_center_y - 45], 
             fill=white, outline=teal, width=3)
draw.ellipse([logo_center_x + 75, logo_center_y - 50, logo_center_x + 105, logo_center_y - 20], 
             fill=white, outline=teal, width=3)

# Bottom right nodes
draw.ellipse([logo_center_x + 100, logo_center_y + 15, logo_center_x + 125, logo_center_y + 40], 
             fill=white, outline=dark_blue, width=3)
draw.ellipse([logo_center_x + 65, logo_center_y + 35, logo_center_x + 90, logo_center_y + 60], 
             fill=white, outline=dark_blue, width=3)

# Connecting lines from center to nodes
draw.line([logo_center_x - 5, logo_center_y - 85, logo_center_x - 100, logo_center_y - 60], 
          fill=dark_green, width=4)
draw.line([logo_center_x - 5, logo_center_y - 35, logo_center_x - 90, logo_center_y - 35], 
          fill=dark_green, width=4)
draw.line([logo_center_x - 5, logo_center_y + 45, logo_center_x - 110, logo_center_y + 25], 
          fill=dark_green, width=4)

draw.line([logo_center_x + 5, logo_center_y - 85, logo_center_x + 100, logo_center_y - 60], 
          fill=teal, width=4)
draw.line([logo_center_x + 5, logo_center_y - 35, logo_center_x + 90, logo_center_y - 35], 
          fill=teal, width=4)
draw.line([logo_center_x + 5, logo_center_y + 45, logo_center_x + 110, logo_center_y + 25], 
          fill=dark_blue, width=4)

# Add text "Study Decoder"
try:
    font_large = ImageFont.truetype("arial.ttf", 80)
except:
    font_large = ImageFont.load_default()

# Draw "Study" in dark blue
text_y = logo_center_y + 140
draw.text((logo_center_x - 250, text_y), "Study", fill=dark_blue, font=font_large)

# Draw "Decoder" in green
draw.text((logo_center_x + 50, text_y), "Decoder", fill=dark_green, font=font_large)

# Save the image
img.save('logo.png')
print('Logo created successfully as logo.png!')
