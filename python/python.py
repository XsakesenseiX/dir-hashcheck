import random

OBJECT_PRONOUNS = ['Her', 'Him', 'Them']
POSSESIVE_PRONOUNS = ['Her', 'His', 'Their']
PERSONAL_PRONOUNS = ['She', 'He', 'They']
STATES = ['California', 'Texas', 'Florida', 'New York', 'Pennsylvannia', 'Illinois', 'Ohio', 'Georgia', 'North Carolina', 'Michigan']
NOUNS = ['Athelete', 'Clown', 'Shovell', 'Paleo Diet', 'Doctor', 'Parent', 'Cat', 'Dog', 'Chicken', 'Robot', 'Video Game', 'Avocado', 'Plastic Straw', 'Serial Killer', 'Telephone Psychic']
PLACES = ['House', 'Attic', 'Bank Deposit Box', 'School', 'Basement', 'Workplace', 'Donut Shop', 'Apocalypse Bunker']
WHEN = ['Soon', 'This Year', 'Later Today', 'RIGHT NOW', 'Next Week']


def main():
    print('Clickbait Headline Generator')
    print('Random Project Automation')
    print()
    print('Our website needs to trick people into looking at ads!')
    while True:
        print = ('Enter the number of clickbait headlines to generates: ')
        response = input('> ')
        if not response.isdecimal():
            print('Please enter a number.')
        else:
            numberofheadlines = int(response)
            break
    

    for i in range (numberofheadlines):
        clickbaitType = random.randint(1, 8)
        if clickbaitType == 1:
            headline = generateAreMillenialsKillingHeadLine()
        elif clickbaitType == 2:
            headline = generateWhatYouDontKnowHeadLine()
        elif clickbaitType == 3:
            headline = generateBigCompaniesHateHerHeadLine()
        elif clickbaitType == 4:
            headline = generateYouWontBelievedHeadLine()
        elif clickbaitType == 5:
            headline = generateDontYouWantToKnowHeadLine()
        elif clickbaitType == 6:
            headline = generateGiftIdeaHeadLine()
        elif clickbaitType == 7:
            headline = generateReasonWhyHeadLine()
        elif clickbaitType == 8:
            headline = generateJobAutomatedHeadLine()

        print(headline)
    print()

    website = random.choice(['wobsite', 'blag', 'Facebuuk', 'Googles', 'Facesbook', 'Tweedie', 'Pastagram'])
    

    when = random.choice(WHEN).lower()
    print('Post these to our', website, when, 'or you\'re fired!')


def generateAreMillenialsKillingHeadLine():
    noun = random.choice(NOUNS)
    return 'Are Millenials Killing the {} Industry?'.format(noun)

def generateWhatYouDontKnowHeadLine():
    noun = random.choice(NOUNS)
    pluralNoun = random.choice(NOUNS) + 's'
    when = random.choice(WHEN)
    return 'Without this {}, {} could Kill You {}'.format(noun, pluralNoun, when)

def generateBigCompaniesHateHerHeadLine():
    pronoun = random.choice(OBJECT_PRONOUNS)
    state = random.choice(STATES)
    noun1 = random.choice(NOUNS)
    noun2 = random.choice(NOUNS)
    return 'Big Companies Hate {}! See How This {} {} Invented a Cheaper {}'.format(pronoun, state, noun1, noun2)

def generateYouWontBelievedHeadLine():
    state = random.choice(STATES)
    noun = random.choice(NOUNS)
    pronoun = random.choice(POSSESIVE_PRONOUNS)
    place = random.choice(PLACES)
    return 'You Won\'t Believe What This {} {} Found in {} {}'.format(state, noun, pronoun, place)

def generateDontYouWantToKnowHeadLine():
    pluralNoun1 = random.choice(NOUNS) + 's'
    pluralNoun2 = random.choice(NOUNS) + 's'
    return 'What {} Don\'t Want You To Know About {}'.format(pluralNoun1, pluralNoun2)

def generateGiftIdeaHeadLine():
    number = random.randint(7, 15)
    noun = random.choice(NOUNS)
    state = random.choice(STATES)
    return '{} Gift Ideas to Give Your {} From {}'.format(number, noun, state)

def generateReasonWhyHeadLine():
    number1 = random.randint(3, 19)
    pluralNoun = random.choice(NOUNS) + 's'
    number2 = random.randint(1, number1)
    return'{} Reasons Why {} Are More Interesting Than You Think (Number {} Will Surprise You!)'.format(number1, pluralNoun, number2)

def generateJobAutomatedHeadLine():
    state = random.choice(STATES)
    noun = random.choice(NOUNS)

    i = random.randint(0, 2)
    pronoun1 = POSSESIVE_PRONOUNS[i]
    pronoun2 = PERSONAL_PRONOUNS[i]
    if pronoun1 == 'Their':
        return 'This {} {} Didn\'t Think Robots Would Take {} Job. Were Wrong'.format(state, noun, pronoun1, pronoun2)
    else:
        return 'This {} {} Didn\'t Think Robots Would Take {} Job. Was Wrong'.format(state, noun, pronoun1, pronoun2)

if __name__ == 'main':
    main()