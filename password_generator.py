import secrets
import string

class PasswordGenerator:
    """Generates secure random passwords"""

    @staticmethod
    def generate(length=16, use_uppercase=True, use_lowercase=True,
                use_digits=True, use_symbols=True):
        """
        Generate a secure random password

        Args:
            length: Length of the password (default: 16)
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            use_digits: Include digits
            use_symbols: Include symbols

        Returns:
            Generated password string
        """
        if length < 4:
            length = 4

        if length > 128:
            length = 128

        # Build character pool
        characters = ''
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        # Ensure at least one character set is selected
        if not characters:
            characters = string.ascii_letters + string.digits

        # Generate password ensuring at least one character from each selected set
        password = []

        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_symbols:
            password.append(secrets.choice(string.punctuation))

        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(secrets.choice(characters))

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    @staticmethod
    def generate_passphrase(word_count=4, separator='-'):
        """
        Generate a memorable passphrase using random words

        Args:
            word_count: Number of words (default: 4)
            separator: Character to separate words (default: '-')

        Returns:
            Generated passphrase string
        """
        # Simple word list for passphrases
        words = [
            'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf',
            'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november',
            'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform',
            'victor', 'whiskey', 'xray', 'yankee', 'zulu', 'apple', 'banana',
            'cherry', 'dragon', 'eagle', 'falcon', 'guitar', 'harbor', 'island',
            'jungle', 'knight', 'lemon', 'mango', 'ninja', 'ocean', 'piano',
            'quartz', 'rocket', 'sunset', 'tiger', 'umbrella', 'violet', 'wizard'
        ]

        selected_words = [secrets.choice(words) for _ in range(word_count)]
        # Add a random number for extra security
        selected_words.append(str(secrets.randbelow(9999)).zfill(4))

        return separator.join(selected_words)
