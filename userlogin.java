import java.util.*;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

class User {
    String username;
    byte[] salt;
    byte[] passwordHash;
    int failedAttempts;
    boolean locked;

    User(String username, char[] password) throws Exception {
        this.username = username;
        this.salt = generateSalt();
        this.passwordHash = hashPassword(password, salt);
        this.failedAttempts = 0;
        this.locked = false;
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    static byte[] hashPassword(char[] password, byte[] salt)
            throws Exception {
        PBEKeySpec spec =
                new PBEKeySpec(password, salt, 120000, 256);

        try {
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    boolean verifyPassword(char[] password) throws Exception {
        byte[] enteredHash = hashPassword(password, salt);

        return java.security.MessageDigest.isEqual(
                passwordHash, enteredHash);
    }
}

public class Main {
    static Scanner sc = new Scanner(System.in);
    static Map<String, User> users = new HashMap<>();

    // Password must contain at least 8 characters,
    // one uppercase, one lowercase, one digit and one special character.
    static boolean validatePassword(String password) {
        if (password.length() < 8) {
            return false;
        }

        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean special = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else {
                special = true;
            }
        }

        return upper && lower && digit && special;
    }

    static void register() {
        try {
            System.out.println("\n--- USER REGISTRATION ---");

            System.out.print("Enter username: ");
            String username = sc.nextLine().trim();

            if (username.isEmpty()) {
                System.out.println("Username cannot be empty.");
                return;
            }

            if (users.containsKey(username)) {
                System.out.println("Username already exists.");
                return;
            }

            System.out.print("Create password: ");
            char[] password = sc.nextLine().toCharArray();

            String passwordText = new String(password);

            if (!validatePassword(passwordText)) {
                System.out.println("Password does not meet requirements.");
                System.out.println("Use at least 8 characters, including:");
                System.out.println("- One uppercase letter");
                System.out.println("- One lowercase letter");
                System.out.println("- One number");
                System.out.println("- One special character");
                Arrays.fill(password, '\0');
                return;
            }

            users.put(username, new User(username, password));
            Arrays.fill(password, '\0');

            System.out.println("Registration successful!");

        } catch (Exception e) {
            System.out.println("Registration failed due to a system error.");
        }
    }

    static void login() {
        try {
            System.out.println("\n--- USER LOGIN ---");

            System.out.print("Enter username: ");
            String username = sc.nextLine().trim();

            User user = users.get(username);

            if (user == null) {
                System.out.println("Invalid username or password.");
                return;
            }

            if (user.locked) {
                System.out.println("Account is locked.");
                return;
            }

            System.out.print("Enter password: ");
            char[] password = sc.nextLine().toCharArray();

            boolean valid = user.verifyPassword(password);
            Arrays.fill(password, '\0');

            if (valid) {
                user.failedAttempts = 0;
                System.out.println("Login successful! Welcome, "
                        + user.username + ".");
                userMenu(user);
            } else {
                user.failedAttempts++;
                System.out.println("Invalid username or password.");

                if (user.failedAttempts >= 3) {
                    user.locked = true;
                    System.out.println(
                            "Account locked after 3 failed login attempts.");
                } else {
                    System.out.println("Attempts remaining: "
                            + (3 - user.failedAttempts));
                }
            }

        } catch (Exception e) {
            System.out.println("Login failed due to a system error.");
        }
    }

    static void userMenu(User user) {
        while (true) {
            System.out.println("\n--- USER DASHBOARD ---");
            System.out.println("1. Change Password");
            System.out.println("2. Logout");
            System.out.print("Choose an option: ");

            String choice = sc.nextLine();

            switch (choice) {
                case "1":
                    changePassword(user);
                    break;

                case "2":
                    System.out.println("Logged out successfully.");
                    return;

                default:
                    System.out.println("Invalid option.");
            }
        }
    }

    static void changePassword(User user) {
        try {
            System.out.println("\n--- CHANGE PASSWORD ---");

            System.out.print("Enter current password: ");
            char[] oldPassword = sc.nextLine().toCharArray();

            boolean valid = user.verifyPassword(oldPassword);
            Arrays.fill(oldPassword, '\0');

            if (!valid) {
                System.out.println("Incorrect current password.");
                return;
            }

            System.out.print("Enter new password: ");
            char[] newPassword = sc.nextLine().toCharArray();
            String newPasswordText = new String(newPassword);

            if (!validatePassword(newPasswordText)) {
                System.out.println("New password does not meet requirements.");
                Arrays.fill(newPassword, '\0');
                return;
            }

            byte[] newSalt = new byte[16];
            new SecureRandom().nextBytes(newSalt);

            byte[] newHash = User.hashPassword(newPassword, newSalt);

            user.salt = newSalt;
            user.passwordHash = newHash;

            Arrays.fill(newPassword, '\0');

            System.out.println("Password changed successfully!");

        } catch (Exception e) {
            System.out.println("Unable to change password.");
        }
    }

    public static void main(String[] args) {
        while (true) {
            System.out.println("\n================================");
            System.out.println(" SECURE USER AUTHENTICATION");
            System.out.println("================================");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");

            String choice = sc.nextLine();

            switch (choice) {
                case "1":
                    register();
                    break;

                case "2":
                    login();
                    break;

                case "3":
                    System.out.println("Thank you for using the system!");
                    sc.close();
                    return;

                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }
}
