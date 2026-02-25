use ratatui::style::Color;

// Basic Terminal Colors
// CLI Color codes
pub const CLI_BLUE: u8 = 69; // Use for general information
pub const CLI_GREEN: u8 = 34; // Use for Successful text
pub const CLI_RED: u8 = 9; // Use for Error messages
pub const CLI_ORANGE: u8 = 214; // Use for cautionary data
pub const CLI_PURPLE: u8 = 165; // Use for Example data
pub const CLI_WHITE: u8 = 15;

// ****************************************************************************

// Ratatui CLI Color codes
/// Success state - Completed actions, valid inputs, positive feedback
pub const COLOR_SUCCESS: Color = Color::Rgb(61, 220, 132); // #3DDC84 - Android Green

///Using bright blue for professional, accessible appearance
pub const COLOR_BORDER: Color = Color::Rgb(97, 175, 239); // #61AFEF - Blue

/// Warning state - Warnings, cautions, important notices, loading/processing
pub const COLOR_ORANGE: Color = Color::Rgb(255, 184, 108); // #FFB86C - Orange

/// Warning state - Accessible red for important warnings and cautions
pub const COLOR_WARNING_ACCESSIBLE_RED: Color = Color::Rgb(220, 100, 100); // #DC6464 - Accessible Red

/// Default text color
pub const COLOR_TEXT_DEFAULT: Color = Color::White;

/// Muted Text
pub const COLOR_DARK_GRAY: Color = Color::DarkGray;

/// Copy/Export actions and sensitive data shortcuts ([C], [C1], [C2], [C3])
/// Soft Purple to distinguish special operations
pub const COLOR_SOFT_PURPLE: Color = Color::Rgb(189, 147, 249); // #BD93F9

/// Darker purple shade for better accessibility
pub const COLOR_DARK_PURPLE: Color = Color::Rgb(156, 112, 231); // #9C70E7 - Darker Purple
