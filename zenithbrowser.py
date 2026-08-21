import sys
import os
import json # For saving/loading history and settings
from PyQt5.QtCore import QUrl, Qt, QSize
from PyQt5.QtWidgets import (QApplication, QMainWindow, QToolBar, QAction,
                             QTabWidget, QWidget, QVBoxLayout, QLineEdit,
                             QMessageBox, QStatusBar, QInputDialog, QProgressBar,
                             QMenu)
from PyQt5.QtWebEngineWidgets import QWebEngineView, QWebEngineProfile, QWebEnginePage
from PyQt5.QtGui import QIcon, QPixmap, QImage

# Ensure 'icons' directory exists for future icon additions
if not os.path.exists('icons'):
    os.makedirs('icons')

# Default search engine
DEFAULT_SEARCH_ENGINE = "https://www.google.com/search?q="
# File paths for persistence
BOOKMARKS_FILE = 'bookmarks.json'
HISTORY_FILE = 'history.json'
SETTINGS_FILE = 'settings.json'

class HttpsOnlyWebEngineView(QWebEngineView):
    """
    A QWebEngineView subclass that blocks navigation to non-HTTPS URLs
    and provides a custom context menu.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.on_context_menu)

    def acceptNavigationRequest(self, url, _type, isMainFrame):
        if url.scheme() == "http":
            print(f"Blocked non-HTTPS URL: {url.toString()}")
            QMessageBox.warning(self.parentWidget(), "Blocked Navigation",
                                "Only HTTPS connections are allowed for security reasons. "
                                f"Blocked: {url.toString()}")
            return False
        return super().acceptNavigationRequest(url, _type, isMainFrame)

    def on_context_menu(self, pos):
        """
        Creates and displays a custom context menu for the web view.
        """
        menu = QMenu(self)

        # Action: Open Link in New Tab
        hit_test_result = self.page().hitTestContent(pos)
        link_url = hit_test_result.linkUrl()
        if link_url.isValid() and link_url.scheme() == "https": # Only allow HTTPS links
            open_new_tab_action = menu.addAction("Open Link in New Tab")
            # We need to access the MainWindow instance to call add_new_tab
            # The parent of HttpsOnlyWebEngineView is BrowserTab (QWidget)
            # The parent of BrowserTab is QTabWidget
            # The parent of QTabWidget is MainWindow
            main_window = self.parent().parent().parent()
            if isinstance(main_window, MainWindow):
                open_new_tab_action.triggered.connect(lambda: main_window.add_new_tab(link_url))
            menu.addSeparator()

        # Action: Copy Link Address
        if link_url.isValid():
            copy_link_action = menu.addAction("Copy Link Address")
            copy_link_action.triggered.connect(lambda: QApplication.clipboard().setText(link_url.toString()))

        # Action: Copy
        copy_action = menu.addAction("Copy")
        copy_action.triggered.connect(self.page().copy)

        # Action: Paste
        paste_action = menu.addAction("Paste")
        paste_action.triggered.connect(self.page().paste)

        menu.addSeparator()

        # Action: Inspect Element (Developer Tools)
        inspect_action = menu.addAction("Inspect Element")
        inspect_action.triggered.connect(lambda: self.page().triggerAction(QWebEnginePage.OpenDevToolsPage))

        menu.exec_(self.mapToGlobal(pos))


class BrowserTab(QWidget):
    """
    Represents a single browser tab, containing a web view.
    """
    def __init__(self, url=QUrl('https://google.com')):
        super().__init__()
        self.browser = HttpsOnlyWebEngineView()
        self.browser.setUrl(url)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0) # Remove margins for a cleaner look
        layout.addWidget(self.browser)
        self.setLayout(layout)

class MainWindow(QMainWindow):
    """
    The main browser window.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure PyBrowser")
        self.setMinimumSize(800, 600)

        # --- Settings ---
        self.settings = {}
        self.load_settings()
        self.search_engine_url = self.settings.get('search_engine', DEFAULT_SEARCH_ENGINE)

        # --- Tab Widget ---
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.update_ui_for_current_tab) # Update UI when tab changes
        self.setCentralWidget(self.tabs)

        # --- Navigation Bar ---
        navbar = QToolBar("Navigation")
        self.addToolBar(navbar)

        # New Tab button
        new_tab_btn = QAction('➕ New Tab', self)
        new_tab_btn.triggered.connect(self.add_new_tab)
        navbar.addAction(new_tab_btn)

        # Navigation Actions
        back_btn = QAction('⬅️ Back', self)
        back_btn.triggered.connect(lambda: self.current_browser().back() if self.current_browser() else None)
        navbar.addAction(back_btn)

        forward_btn = QAction('➡️ Forward', self)
        forward_btn.triggered.connect(lambda: self.current_browser().forward() if self.current_browser() else None)
        navbar.addAction(forward_btn)

        reload_btn = QAction('🔄 Reload', self)
        reload_btn.triggered.connect(lambda: self.current_browser().reload() if self.current_browser() else None)
        navbar.addAction(reload_btn)

        home_btn = QAction('🏠 Home', self)
        home_btn.triggered.connect(self.navigate_home)
        navbar.addAction(home_btn)

        # URL bar
        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.navigate_to_url_or_search)
        self.url_bar.setPlaceholderText("Enter URL or search (e.g., example.com or 'weather')")
        navbar.addWidget(self.url_bar)

        # HTTPS Lock Icon
        self.https_lock_icon = QAction(self)
        # Initialize with an empty icon, it will be updated dynamically
        self.https_lock_icon.setIcon(QIcon())
        self.https_lock_icon.setToolTip("Connection Status")
        navbar.addAction(self.https_lock_icon)


        # --- Bookmarks ---
        self.bookmarks = []
        self.load_bookmarks() # Load bookmarks on startup

        bookmark_btn = QAction('⭐ Bookmark', self)
        bookmark_btn.triggered.connect(self.add_bookmark)
        navbar.addAction(bookmark_btn)

        show_bookmarks_btn = QAction('📚 Show Bookmarks', self)
        show_bookmarks_btn.triggered.connect(self.show_bookmarks)
        navbar.addAction(show_bookmarks_btn)

        # --- History ---
        self.history = []
        self.load_history()

        history_btn = QAction('🕒 History', self)
        history_btn.triggered.connect(self.show_history)
        navbar.addAction(history_btn)

        # --- Additional Features Toolbar ---
        features_toolbar = QToolBar("Features")
        self.addToolBar(features_toolbar)

        # Zoom
        zoom_in_btn = QAction('🔍+ Zoom In', self)
        zoom_in_btn.triggered.connect(lambda: self.current_browser().setZoomFactor(self.current_browser().zoomFactor() + 0.1) if self.current_browser() else None)
        features_toolbar.addAction(zoom_in_btn)

        zoom_out_btn = QAction('🔍- Zoom Out', self)
        zoom_out_btn.triggered.connect(lambda: self.current_browser().setZoomFactor(self.current_browser().zoomFactor() - 0.1) if self.current_browser() else None)
        features_toolbar.addAction(zoom_out_btn)

        reset_zoom_btn = QAction('🔍100% Reset Zoom', self)
        reset_zoom_btn.triggered.connect(lambda: self.current_browser().setZoomFactor(1.0) if self.current_browser() else None)
        features_toolbar.addAction(reset_zoom_btn)

        # Full Screen
        fullscreen_btn = QAction('📺 Full Screen', self)
        fullscreen_btn.triggered.connect(self.toggle_fullscreen)
        features_toolbar.addAction(fullscreen_btn)
        self.is_fullscreen = False

        # Developer Tools
        dev_tools_btn = QAction('🛠️ Dev Tools', self)
        dev_tools_btn.triggered.connect(self.open_dev_tools)
        features_toolbar.addAction(dev_tools_btn)

        # Set Custom User Agent (Example)
        set_ua_btn = QAction('👤 Set User Agent', self)
        set_ua_btn.triggered.connect(self.set_custom_user_agent)
        features_toolbar.addAction(set_ua_btn)
        # Default user agent for the browser profile
        QWebEngineProfile.defaultProfile().setHttpUserAgent("PyBrowser/1.0 (Secure; Python PyQt5)")

        # Change Search Engine
        change_search_engine_btn = QAction('⚙️ Search Engine', self)
        change_search_engine_btn.triggered.connect(self.change_search_engine)
        features_toolbar.addAction(change_search_engine_btn)


        # --- Status Bar ---
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Progress Bar in Status Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(150)
        self.progress_bar.setTextVisible(False) # Hide percentage text
        self.progress_bar.hide() # Hide until loading starts
        self.status_bar.addPermanentWidget(self.progress_bar)


        # Initial tab
        self.add_new_tab(QUrl('https://google.com'))
        self.update_ui_for_current_tab() # Initial update

        # Connect download manager
        QWebEngineProfile.defaultProfile().downloadRequested.connect(self.on_download_requested)

    def current_browser(self):
        """
        Returns the QWebEngineView instance of the currently active tab.
        """
        current_widget = self.tabs.currentWidget()
        return current_widget.browser if isinstance(current_widget, BrowserTab) else None

    def add_new_tab(self, url=QUrl('https://google.com')):
        """
        Adds a new browser tab with the given URL.
        """
        # Defensive check: Ensure 'url' is a QUrl object.
        # This helps prevent TypeErrors if a signal accidentally passes a non-QUrl type.
        if not isinstance(url, QUrl):
            print(f"Warning: add_new_tab received unexpected type for URL: {type(url)}. Defaulting to Google.")
            url = QUrl('https://google.com') # Fallback to default if type is wrong

        tab = BrowserTab(url)
        index = self.tabs.addTab(tab, "New Tab")
        self.tabs.setCurrentIndex(index)

        # Connect signals for updating UI elements
        tab.browser.urlChanged.connect(lambda q, browser=tab.browser: self.update_url_bar(q, browser))
        tab.browser.titleChanged.connect(lambda title, browser=tab.browser: self.update_tab_title(title, browser))
        tab.browser.loadFinished.connect(lambda success, browser=tab.browser: self.load_finished(success, browser))
        tab.browser.loadProgress.connect(lambda p, browser=tab.browser: self.update_load_progress(p, browser))
        # Corrected: linkHovered is a signal of QWebEnginePage, not QWebEngineView
        tab.browser.page().linkHovered.connect(self.show_link_hovered_url)
        tab.browser.iconChanged.connect(lambda icon, browser=tab.browser: self.update_tab_icon(icon, browser))

        # Clear URL bar for a fresh start on a new tab
        self.url_bar.clear()

    def close_tab(self, index):
        """
        Closes the tab at the given index. Prevents closing the last tab.
        """
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)
        else:
            QMessageBox.information(self, "Cannot Close Tab", "You cannot close the last tab.")

    def navigate_home(self):
        """
        Navigates the current browser tab to the default home page.
        """
        browser = self.current_browser()
        if browser:
            try:
                browser.setUrl(QUrl('https://google.com'))
            except Exception as e:
                QMessageBox.critical(self, "Navigation Error", f"Failed to navigate home: {e}")

    def navigate_to_url_or_search(self):
        """
        Navigates to the entered URL or performs a search if it's not a valid URL.
        """
        text = self.url_bar.text().strip()
        if not text:
            return

        # Check if it looks like a URL
        # A simple check: if it starts with a scheme or contains a dot and doesn't contain spaces
        if (text.startswith(('http://', 'https://')) or ('.' in text and ' ' not in text)):
            url = QUrl(text)
            if not url.scheme(): # If no scheme, default to https
                url.setScheme('https')
            if self.current_browser():
                self.current_browser().setUrl(url)
                self.add_to_history(url.toString())
        else:
            # Assume it's a search query
            search_url = QUrl(self.search_engine_url + QUrl.toPercentEncoding(text))
            if self.current_browser():
                self.current_browser().setUrl(search_url)
                self.add_to_history(search_url.toString())

    def update_url_bar(self, url, browser):
        """
        Updates the URL bar with the current URL of the specified browser.
        Ensures the update only happens if the tab is currently active.
        Also updates the HTTPS lock icon.
        """
        if self.tabs.currentWidget() and self.tabs.currentWidget().browser == browser:
            self.url_bar.setText(url.toString())
            self.url_bar.setCursorPosition(0) # Go to the beginning of the URL

            # Update HTTPS lock icon
            if url.scheme() == "https":
                # Attempt to load the built-in lock icon
                lock_pixmap = QPixmap(":/qtwebengine/icons/lock.png")
                if not lock_pixmap.isNull():
                    self.https_lock_icon.setIcon(QIcon(lock_pixmap.scaled(16, 16, Qt.KeepAspectRatio, Qt.SmoothTransformation)))
                    self.https_lock_icon.setToolTip("Secure (HTTPS)")
                else:
                    # Fallback if built-in icon is not found
                    self.https_lock_icon.setIcon(QIcon()) # Clear icon
                    self.https_lock_icon.setToolTip("Secure (HTTPS) - Icon not loaded. Resource missing.")
                    print("Warning: Built-in lock icon not found. Using empty icon.")
            else:
                self.https_lock_icon.setIcon(QIcon()) # Clear icon for non-HTTPS
                self.https_lock_icon.setToolTip("Insecure or No Connection")

    def update_tab_title(self, title, browser):
        """
        Updates the title of the tab associated with the given browser.
        """
        for i in range(self.tabs.count()):
            if self.tabs.widget(i).browser == browser:
                self.tabs.setTabText(i, title or "New Tab")
                break

    def update_tab_icon(self, icon, browser):
        """
        Updates the favicon of the tab associated with the given browser.
        """
        for i in range(self.tabs.count()):
            if self.tabs.widget(i).browser == browser:
                self.tabs.setTabIcon(i, icon)
                break

    def update_load_progress(self, progress, browser):
        """
        Updates the progress bar in the status bar.
        """
        if self.tabs.currentWidget() and self.tabs.currentWidget().browser == browser:
            if progress < 100:
                self.progress_bar.show()
                self.progress_bar.setValue(progress)
                self.status_bar.showMessage(f"Loading: {progress}%", 0) # 0 means message stays until new one
            else:
                self.progress_bar.hide()
                self.status_bar.clearMessage()


    def load_finished(self, success, browser):
        """
        Handles actions after a page load finishes. Updates URL bar and tab title.
        Adds to history if successful.
        """
        if success:
            self.update_url_bar(browser.url(), browser)
            self.update_tab_title(browser.title(), browser)
            self.add_to_history(browser.url().toString())
            self.status_bar.showMessage(f"Page loaded: {browser.url().toString()}", 3000)
        else:
            QMessageBox.warning(self, "Page Load Error", f"Could not load page: {browser.url().toString()}")
            self.status_bar.showMessage(f"Page load failed: {browser.url().toString()}", 5000)

        self.progress_bar.hide() # Ensure progress bar hides on load finish

    def update_ui_for_current_tab(self):
        """
        Updates the URL bar and other UI elements when the active tab changes.
        """
        browser = self.current_browser()
        if browser:
            self.update_url_bar(browser.url(), browser)
            self.update_tab_title(browser.title(), browser)
            self.update_tab_icon(browser.icon(), browser)
        else:
            self.url_bar.clear()
            self.tabs.setTabText(self.tabs.currentIndex(), "New Tab") # Fallback for no browser
            self.https_lock_icon.setIcon(QIcon()) # Clear icon

    def add_bookmark(self):
        """
        Adds the current page's URL to the bookmarks list and saves it.
        """
        browser = self.current_browser()
        if browser:
            url = browser.url().toString()
            title = browser.title() or "Untitled"
            bookmark_entry = {"url": url, "title": title}

            # Check if the URL is already bookmarked to avoid duplicates
            if not any(b['url'] == url for b in self.bookmarks):
                self.bookmarks.append(bookmark_entry)
                self.save_bookmarks()
                QMessageBox.information(self, "Bookmarked", f"Added '{title}' to bookmarks!")
            else:
                QMessageBox.information(self, "Bookmark", "This page is already bookmarked or URL is empty.")

    def show_bookmarks(self):
        """
        Displays a list of saved bookmarks in a message box.
        Allows navigating to a bookmark by clicking on it.
        """
        if not self.bookmarks:
            QMessageBox.information(self, "Bookmarks", "No bookmarks yet.")
            return

        bookmarks_text = "\n".join(f"{i+1}. {b['title']} ({b['url']})" for i, b in enumerate(self.bookmarks))
        reply = QMessageBox.information(self, "Bookmarks", "Your Bookmarks:\n\n" + bookmarks_text +
                                        "\n\nEnter the number of the bookmark to navigate (or cancel):",
                                        QMessageBox.Ok | QMessageBox.Cancel)

        if reply == QMessageBox.Ok:
            text, ok = QInputDialog.getText(self, "Navigate to Bookmark",
                                            "Enter bookmark number:")
            if ok and text.isdigit():
                try:
                    index = int(text) - 1
                    if 0 <= index < len(self.bookmarks):
                        self.add_new_tab(QUrl(self.bookmarks[index]['url']))
                    else:
                        QMessageBox.warning(self, "Invalid Input", "Invalid bookmark number.")
                except ValueError:
                    QMessageBox.warning(self, "Invalid Input", "Please enter a valid number.")

    def load_bookmarks(self):
        """
        Loads bookmarks from a JSON file.
        """
        if os.path.exists(BOOKMARKS_FILE):
            try:
                with open(BOOKMARKS_FILE, 'r') as f:
                    self.bookmarks = json.load(f)
            except json.JSONDecodeError:
                self.bookmarks = [] # Reset if file is corrupt
                print(f"Warning: Could not decode {BOOKMARKS_FILE}. Starting with empty bookmarks.")

    def save_bookmarks(self):
        """
        Saves the current bookmarks to a JSON file.
        """
        with open(BOOKMARKS_FILE, 'w') as f:
            json.dump(self.bookmarks, f, indent=4)

    def add_to_history(self, url):
        """
        Adds a URL to the browsing history, ensuring no duplicates and limited size.
        """
        if url:
            # Remove existing entry if URL is already in history (to move it to top)
            self.history = [item for item in self.history if item != url]
            self.history.insert(0, url) # Add to the beginning
            # Keep history size manageable (e.g., last 100 entries)
            self.history = self.history[:100]
            self.save_history()

    def show_history(self):
        """
        Displays the browsing history and allows navigating to a past URL.
        """
        if not self.history:
            QMessageBox.information(self, "History", "No browsing history yet.")
            return

        history_text = "\n".join(f"{i+1}. {url}" for i, url in enumerate(self.history))
        reply = QMessageBox.information(self, "History", "Your Browsing History:\n\n" + history_text +
                                        "\n\nEnter the number of the history item to navigate (or cancel):",
                                        QMessageBox.Ok | QMessageBox.Cancel)

        if reply == QMessageBox.Ok:
            text, ok = QInputDialog.getText(self, "Navigate to History Item",
                                            "Enter history item number:")
            if ok and text.isdigit():
                try:
                    index = int(text) - 1
                    if 0 <= index < len(self.history):
                        self.add_new_tab(QUrl(self.history[index]))
                    else:
                        QMessageBox.warning(self, "Invalid Input", "Invalid history item number.")
                except ValueError:
                    QMessageBox.warning(self, "Invalid Input", "Please enter a valid number.")

    def load_history(self):
        """
        Loads browsing history from a JSON file.
        """
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, 'r') as f:
                    self.history = json.load(f)
            except json.JSONDecodeError:
                self.history = []
                print(f"Warning: Could not decode {HISTORY_FILE}. Starting with empty history.")

    def save_history(self):
        """
        Saves the current browsing history to a JSON file.
        """
        with open(HISTORY_FILE, 'w') as f:
            json.dump(self.history, f, indent=4)

    def load_settings(self):
        """
        Loads application settings from a JSON file.
        """
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, 'r') as f:
                    self.settings = json.load(f)
            except json.JSONDecodeError:
                self.settings = {}
                print(f"Warning: Could not decode {SETTINGS_FILE}. Starting with default settings.")

    def save_settings(self):
        """
        Saves application settings to a JSON file.
        """
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(self.settings, f, indent=4)

    def toggle_fullscreen(self):
        """
        Toggles the browser window between normal and full screen modes.
        """
        if self.is_fullscreen:
            self.showNormal()
            self.is_fullscreen = False
        else:
            self.showFullScreen()
            self.is_fullscreen = True

    def open_dev_tools(self):
        """
        Opens the developer tools for the current browser tab.
        """
        browser = self.current_browser()
        if browser:
            browser.page().triggerAction(QWebEnginePage.OpenDevToolsPage)
        else:
            QMessageBox.information(self, "Developer Tools", "No active browser tab to open Dev Tools.")

    def set_custom_user_agent(self):
        """
        Allows the user to set a custom user agent for the browser profile.
        """
        current_ua = QWebEngineProfile.defaultProfile().httpUserAgent()
        text, ok = QInputDialog.getText(self, "Set User Agent", "Enter custom user agent string:",
                                        QLineEdit.Normal, current_ua)
        if ok and text:
            QWebEngineProfile.defaultProfile().setHttpUserAgent(text)
            QMessageBox.information(self, "User Agent Set", f"User Agent set to: {text}\n"
                                    "Changes will apply to newly loaded pages.")
        elif ok: # User clicked OK but entered empty string
            QMessageBox.warning(self, "User Agent", "User agent cannot be empty. Reverting to default.")
            QWebEngineProfile.defaultProfile().setHttpUserAgent("PyBrowser/1.0 (Secure; Python PyQt5)")

    def change_search_engine(self):
        """
        Allows the user to change the default search engine URL.
        """
        current_engine = self.search_engine_url
        text, ok = QInputDialog.getText(self, "Change Search Engine",
                                        "Enter new search engine URL (e.g., 'https://duckduckgo.com/?q=' or 'https://www.bing.com/search?q=')",
                                        QLineEdit.Normal, current_engine)
        if ok and text:
            # Basic validation for search query placeholder
            if not any(placeholder in text for placeholder in ["?q=", "?query=", "%s"]):
                QMessageBox.warning(self, "Invalid URL", "Please ensure the URL includes a query placeholder "
                                    "(e.g., '?q=', '?query=', or '%s').")
                return
            self.search_engine_url = text
            self.settings['search_engine'] = text
            self.save_settings()
            QMessageBox.information(self, "Search Engine Updated", f"Default search engine set to: {text}")
        elif ok:
            QMessageBox.warning(self, "Search Engine", "Search engine URL cannot be empty.")

    def on_download_requested(self, download):
        """
        Handles download requests. Asks user for confirmation and then starts download.
        """
        reply = QMessageBox.question(self, "Download Request",
                                     f"Do you want to download: {download.url().fileName()}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            # You can set a default download directory here
            download_dir = os.path.join(os.path.expanduser("~"), "Downloads")
            os.makedirs(download_dir, exist_ok=True) # Ensure download directory exists
            download_path = os.path.join(download_dir, download.url().fileName())
            download.setPath(download_path)
            download.accept()
            QMessageBox.information(self, "Download", f"Download of '{download.url().fileName()}' started to:\n{download_path}")
            download.stateChanged.connect(lambda state: self.on_download_state_changed(download, state))
        else:
            download.cancel()
            QMessageBox.information(self, "Download", f"Download of '{download.url().fileName()}' cancelled.")

    def on_download_state_changed(self, download, state):
        """
        Monitors the state of a download and provides feedback.
        """
        if state == download.DownloadStateCompleted:
            self.status_bar.showMessage(f"Download completed: {download.url().fileName()}", 5000)
        elif state == download.DownloadStateFailed:
            self.status_bar.showMessage(f"Download failed: {download.url().fileName()}", 5000)
        elif state == download.DownloadStateCancelled:
            self.status_bar.showMessage(f"Download cancelled: {download.url().fileName()}", 5000)

    def show_link_hovered_url(self, url):
        """
        Displays the URL of the link currently hovered over in the status bar.
        """
        self.status_bar.showMessage(url)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName("PyBrowser")
    app.setWindowIcon(QIcon(os.path.join('icons', 'browser_icon.png'))) # Optional: Add a custom icon

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())