# this file includes urls as content management system
def Content():
  TOPIC_DICT = {"Basics":[["Introduction to Python","/introduction-to-python-programming/"],
                            ["Print functions and Strings","/python-tutorial-print-function-strings/"],
                            ["Math basics with Python 3","/math-basics-python-3-beginner-tutorial/"]],
                  "Web Dev":[]}
  return TOPIC_DICT


def Urls():
  URLS = {
    "Urls" : [
      ["Dashboard", "/dashboard"],
      ["About", "/about"]
    ]
  }
  return URLS
