import os
import pickle
import json
# pyrefly: ignore [missing-import]
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix

# Define our synthetic dataset of scams and safe messages
dataset = [
    # --- OTP Scam ---
    ("Your OTP code for transaction of $500 is 884920. If you did not request this, please verify your identity immediately by calling our fraud support.", "OTP Scam"),
    ("Use verification code 281928 to complete login. Keep this code secret. Employees will never ask for this code.", "OTP Scam"),
    ("OTP request: 928374 is your security code to authorize a new device. If this was not you, update your settings.", "OTP Scam"),
    ("To verify your mobile number, enter code 103984 in the screen. Do not share this OTP with anyone.", "OTP Scam"),
    ("A login attempt was made from Chrome on Android. Use code 551932 to approve or click details to block.", "OTP Scam"),
    ("Your verification code is 492019. It will expire in 5 minutes.", "OTP Scam"),
    ("Do not share your verification pin. The temporary code is 283928.", "OTP Scam"),
    ("Your security authorization pin is 839281. Call customer service if you did not request this OTP.", "OTP Scam"),
    ("ALERT: Confirm bank transfer of $1000. Your OTP code is 492018. Never share this with support agents.", "OTP Scam"),
    ("Sign-in verification code: 382910. Valid for 10 minutes only.", "OTP Scam"),
    
    # --- Banking Scam ---
    ("URGENT: Your Chase bank account has been suspended due to suspicious activity. Verify your identity at http://chase-security-verify.com to restore access.", "Banking Scam"),
    ("ALERT: We detected a suspicious login attempt on your account. Please confirm your details immediately at http://security-banking-portal.net", "Banking Scam"),
    ("Your debit card has been temporarily locked. Please log in at http://bank-card-unlock.com to verify your transactions.", "Banking Scam"),
    ("Bank notification: Your profile details need updating before 24 hours to avoid suspension. Update now at http://bank-update-portal.com", "Banking Scam"),
    ("Wells Fargo alert: A new payee was added. If you do not recognize this, cancel it at http://wellsfargo-cancel-payee.com", "Banking Scam"),
    ("Verify your Bank of America account security settings to prevent transfer block. Access portal here: http://bofa-verify-link.com", "Banking Scam"),
    ("Your credit card statement indicates abnormal activities. Verify your identity at http://bank-identity-restore.com", "Banking Scam"),
    ("Security alert: Unauthorized access detected. Verify your credentials: http://bank-login-secure.com", "Banking Scam"),
    ("Confirm your billing address for bank card reactivation: http://reactivate-bankcard.com", "Banking Scam"),
    ("Important notice: Your account profile is missing required tax details. Rectify here: http://bank-tax-profile.com", "Banking Scam"),

    # --- Job Scam ---
    ("Work from home part-time and earn $500 to $1200 daily! Training is free. Click here to contact our recruiter on Telegram.", "Job Scam"),
    ("Immediate hiring! Earn up to $4000/week copying data. No experience needed. Apply at http://easywork-recruit.com", "Job Scam"),
    ("Congratulations! Your resume has been selected for the position of online manager. Salary: $35/hour. Contact us on WhatsApp for onboarding.", "Job Scam"),
    ("Earn passive income from home! Task assistant jobs available. 1 hour/day, earn $200. Apply at http://homeincome-agent.org", "Job Scam"),
    ("HIRING NOW: Customer review specialist. Earn up to $1000 a week using your mobile device. Contact recruiting manager.", "Job Scam"),
    ("Earn money by testing apps from your couch. $300 per day guaranteed. Text us back to receive your setup instructions.", "Job Scam"),
    ("We have a job offer for you. Earn $30 per task from home. Flexible hours. Open link to register: http://apply-easyjob.com", "Job Scam"),
    ("Remote work project manager wanted immediately. Salary starts at $4500 monthly. No skills required. Apply at http://fastcareer-inc.com", "Job Scam"),
    ("Flexible part-time work from home. Make $150/hr using social media. Sign up here: http://socialjob-earn.com", "Job Scam"),
    ("Your application for the virtual assistant position was approved. Initial salary $3500. Message us to activate.", "Job Scam"),

    # --- Lottery Scam ---
    ("Congratulations! Your mobile number won the second prize in the annual mega draw. You won £500,000! Contact claim-agent@prize-draw.co.uk to claim.", "Lottery Scam"),
    ("You are selected! You won $10,000,000 cash in our exclusive raffle. Text CLAIM to 88392 to receive your payout instructions.", "Lottery Scam"),
    ("Winner announcement: Your email won the 2026 Promo Prize of $2,000,000. Send your name, address, and mobile number to claim agent.", "Lottery Scam"),
    ("You have won a free Chevrolet Cruze and a cash sum of $50,000 in the UK Lottery. Contact agent to claim.", "Lottery Scam"),
    ("Mega Millions Notice: Ticket #482910 matched 5 numbers. You won $100,000. Go to http://megamillions-claim-prize.com to register.", "Lottery Scam"),
    ("Congratulations! You won the grand cash prize of $5,000 in our customer satisfaction raffle. Access details: http://raffle-winner.com", "Lottery Scam"),
    ("Your mobile number has won a lottery worth $1,000,000 from our anniversary draw. Email us for instructions.", "Lottery Scam"),
    ("Important notice: You won a $1,000 Walmart Gift Card! Complete this short survey to claim: http://giftcard-survey-win.com", "Lottery Scam"),
    ("ALERT: You won a prize in our monthly sweepstakes. Call customer service to register your prize claim details.", "Lottery Scam"),
    ("Official notice: You are the lucky winner of our cash giveaway. Claim within 48 hours: http://cash-giveaway-winner.net", "Lottery Scam"),

    # --- Investment Scam ---
    ("Invest just $200 and earn $5,000 guaranteed returns in 48 hours! Crypto trading bot handles everything. Sign up at http://double-bitcoin-fast.com", "Investment Scam"),
    ("Turn your savings into a fortune. Double your crypto deposits daily. Guaranteed returns with no risk. Contact us for details.", "Investment Scam"),
    ("Get 500% ROI in just 1 week trading forex. Automated AI system guarantees zero losses. Join our Telegram group now.", "Investment Scam"),
    ("Earn passive income of $3000 weekly from safe real estate stocks. Minimum capital only $100. Join our webinar at http://guaranteed-wealth.net", "Investment Scam"),
    ("Bitcoin mining investment opportunities. Earn 20% interest daily compounded. Register account at http://btc-yield-mining.com", "Investment Scam"),
    ("Get rich quick with our algorithmic trading software. 99% accuracy, zero risks. Register at http://algorithmic-rich.com", "Investment Scam"),
    ("Crypto token presale: 100x return potential guaranteed by top tech experts. Buy now before prices surge: http://100x-presale-token.com", "Investment Scam"),
    ("High yield deposit program: Earn 10% daily return on gold and oil assets. Trusted by millions. Join http://highyield-deposit.com", "Investment Scam"),
    ("Want to make passive income? Invest $50 and receive $1,000 payouts every week. Message trading advisor directly.", "Investment Scam"),
    ("Double your cash in 3 days. Professional trading panel handles everything. Send deposit to crypto wallet.", "Investment Scam"),

    # --- Loan Scam ---
    ("Urgent loans needed? Bad credit is not a problem. Get approved for up to $50,000 in 1 hour. Apply now at http://fast-loan-lenders.com", "Loan Scam"),
    ("Pre-approved for a personal loan of $15,000 at 1.5% interest rate. No collateral, no background checks. Claim loan: http://preapproved-loans.net", "Loan Scam"),
    ("Need cash fast? Payday loans up to $5,000. Apply in 5 minutes, money sent to card instantly. Apply here: http://quick-cash-loans.com", "Loan Scam"),
    ("Emergency cash advance! Get up to $10,000 deposited today. Low interest, monthly payments. No credit checks: http://emergency-advance.com", "Loan Scam"),
    ("Get debt relief loans up to $100,000. Pay off all credit cards with one low monthly payment. Check qualification: http://debt-relief-loans.net", "Loan Scam"),
    ("Approved notice: Personal loan of $20,000 is ready for transfer. Pay processing fee of $150 to activate deposit.", "Loan Scam"),
    ("No credit history check loans. Fast decision, guaranteed approval. Apply at http://nocreditcheck-loans.com", "Loan Scam"),
    ("Get business funding loans up to $250,000. Simple documentation, quick approval. Apply online: http://businessfunding-portal.com", "Loan Scam"),
    ("Special offer: Payday cash loan with zero interest for first 30 days. Register account: http://payday-cash-free.net", "Loan Scam"),
    ("Your loan request was pre-screened. Get up to $30,000. Complete application steps at http://prescreened-lenders.com", "Loan Scam"),

    # --- Prize Scam ---
    ("Dear customer, you won a free Amazon gift card worth $500. Enter details at http://amazon-giftcard-claims.com to redeem your voucher.", "Prize Scam"),
    ("Congratulations! You are the visitor of the day and won a free iPad Pro. Click here to confirm shipping details: http://ipadpro-delivery.com", "Prize Scam"),
    ("Your package has a pending delivery charge. Complete the form to pay shipping and claim your gift: http://post-package-delivery.net", "Prize Scam"),
    ("Claim your free $100 Starbucks gift coupon code today. Limited quantity. Redeem voucher at http://starbucks-coupons-win.com", "Prize Scam"),
    ("Congratulations! You won a free vacation to Hawaii. Fill out questionnaire to secure your tickets: http://hawaii-holiday-win.com", "Prize Scam"),
    ("You got selected for a loyalty reward. Claim a free mystery mystery box worth $300. Register address: http://loyalty-rewards-box.net", "Prize Scam"),
    ("Congratulations on winning the shopper reward of $250. Click link to verify your email address: http://reward-shopper.com", "Prize Scam"),
    ("Claim your free gaming console now! Enter giveaway winner code at http://gamingconsole-claims.com", "Prize Scam"),
    ("You are today's lucky winner of a $50 cash credit. Withdraw money here: http://lucky-visitor-cash.com", "Prize Scam"),
    ("Claim a free pair of designer shoes. Simply pay $1 for shipping validation: http://designershoes-promo.com", "Prize Scam"),

    # --- Phishing Scam ---
    ("Your Netflix account has been suspended due to billing details error. Update your credit card details immediately at http://netflix-billing-update.com", "Phishing Scam"),
    ("Your PayPal account was locked due to security concerns. Log in here to verify your identity and unlock: http://paypal-identity-check.com", "Phishing Scam"),
    ("UPS alert: Your package is on hold because of an incorrect shipping address. Correct details here: http://ups-package-update.com", "Phishing Scam"),
    ("Facebook alert: Security breach detected on your profile. Log in here to secure your account: http://facebook-security-recovery.com", "Phishing Scam"),
    ("Your Microsoft password expires today. Keep the same password by logging in: http://outlook-password-renew.com", "Phishing Scam"),
    ("Apple ID notice: suspicious purchase detected. Cancel transaction at http://appleid-activity-cancel.com to protect details.", "Phishing Scam"),
    ("Your tax refund is ready. Submit your online tax file containing bank details: http://government-tax-refund.org", "Phishing Scam"),
    ("DocuSign: You received a secure contract document. Sign in with your email provider to view: http://docusign-provider-login.com", "Phishing Scam"),
    ("Your Google account storage is full. Increase storage limits by verifying your account login: http://google-storage-billing.com", "Phishing Scam"),
    ("DHL delivery alert: Package failed delivery. Update address details to schedule re-delivery: http://dhl-package-update.com", "Phishing Scam"),

    # --- Safe ---
    ("Hey, are we still meeting today at 5 PM for coffee at Starbucks?", "Safe"),
    ("Can you please send me the project report by tomorrow morning? Thanks.", "Safe"),
    ("Hi Mom, just calling to check on you. Let me know when you are free to chat.", "Safe"),
    ("Your appointment with Dr. Smith is scheduled for next Tuesday at 10:30 AM. Call to reschedule.", "Safe"),
    ("Hey! Don't forget to buy milk and bread on your way home.", "Safe"),
    ("The team meeting is moved to Room 402. We will start at 2:00 PM instead of 1:30.", "Safe"),
    ("Just wanted to say congratulations on your promotion! You deserve it.", "Safe"),
    ("Hi, here is the link to the Google Doc we discussed in class: https://docs.google.com/document/d/xyz", "Safe"),
    ("Thanks for the lunch today. We should do it again sometime next week.", "Safe"),
    ("Are you coming to the movie tonight? Let me know if I should book your ticket.", "Safe"),
    ("Hi, I received the draft and will review it this evening. Talk to you tomorrow.", "Safe"),
    ("Can you pick up the kids from school today? I have a late meeting.", "Safe"),
    ("Your reservation at the Italian Restaurant is confirmed for 4 people at 7:30 PM.", "Safe"),
    ("Hey, I left my keys at your apartment. Can I drop by to get them later?", "Safe"),
    ("Your order has been shipped and is scheduled to arrive tomorrow. Tracking: 9283719.", "Safe"),
    ("Hi there, just wanted to check if you got my email from yesterday. No rush.", "Safe"),
    ("The weather looks great for a hike tomorrow. Let's meet at the trailhead at 8 AM.", "Safe"),
    ("I am running 10 minutes late. Sorry, see you soon!", "Safe"),
    ("Can we reschedule our phone call to next Monday afternoon? I have a conflict.", "Safe"),
    ("Thank you for the birthday wishes! I appreciate it.", "Safe"),
]

# Duplicate the dataset with minor variations to increase size and stability of models
augmented_dataset = []
for text, label in dataset:
    augmented_dataset.append((text, label))
    # Variation 1: lower case
    augmented_dataset.append((text.lower(), label))
    # Variation 2: slightly altered text
    if label == "Safe":
        augmented_dataset.append((f"Hello, {text}", label))
    else:
        augmented_dataset.append((f"IMPORTANT: {text}", label))

df = pd.DataFrame(augmented_dataset, columns=['text', 'label'])

def train_and_evaluate():
    print(f"Loaded synthetic dataset with {len(df)} samples.")
    
    # Split features and labels
    X = df['text']
    y = df['label']
    
    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    
    # Text Vectorization using TF-IDF
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), stop_words='english', min_df=1)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    # Save the vectorizer
    models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
    os.makedirs(models_dir, exist_ok=True)
    
    with open(os.path.join(models_dir, 'vectorizer.pkl'), 'wb') as f:
        pickle.dump(vectorizer, f)
    
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000, random_state=42),
        'Naive Bayes': MultinomialNB(),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42)
    }
    
    metrics_summary = {}
    
    for model_name, model in models.items():
        print(f"\nTraining {model_name}...")
        model.fit(X_train_vec, y_train)
        
        # Predictions
        y_pred = model.predict(X_test_vec)
        
        # Evaluation metrics
        acc = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
        
        print(f"{model_name} Accuracy: {acc:.4f} | Precision: {precision:.4f} | Recall: {recall:.4f} | F1: {f1:.4f}")
        
        # Save model
        model_filename = model_name.lower().replace(' ', '_') + '.pkl'
        with open(os.path.join(models_dir, model_filename), 'wb') as f:
            pickle.dump(model, f)
            
        # Generate Confusion Matrix
        labels_list = sorted(list(set(y)))
        cm = confusion_matrix(y_test, y_pred, labels=labels_list)
        
        # Convert classification report to dict
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        
        # Format metrics and confusion matrix for front-end
        metrics_summary[model_name] = {
            'accuracy': round(acc * 100, 2),
            'precision': round(precision * 100, 2),
            'recall': round(recall * 100, 2),
            'f1_score': round(f1 * 100, 2),
            'confusion_matrix': cm.tolist(),
            'labels': labels_list,
            'report': report
        }
        
    # Save metrics data
    metrics_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model_metrics.json')
    with open(metrics_path, 'w') as f:
        json.dump(metrics_summary, f, indent=4)
        
    print(f"\nModel training complete. Performance metrics saved to '{metrics_path}'.")

if __name__ == '__main__':
    train_and_evaluate()
