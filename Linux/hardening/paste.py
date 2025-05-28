import pyautogui
import time
import pyperclip

# Function to take user input, wait, and then type the input using pyautogui
def type_with_macro():
    user_input = pyperclip.paste()

    print("You have 5 seconds to switch to the window where the text should be typed...")
    time.sleep(5)

    pyautogui.write(user_input, interval=0.01)  # Adjust interval if needed for slower typing

type_with_macro()
