using org.bouncycastle.jce.provider;

// Copyright (c) 2005 The Legion Of The Bouncy Castle (http://www.bouncycastle.org)
namespace org.bouncycastle.mail.smime.test
{
	using TestSetup = junit.extensions.TestSetup;
	using Test = junit.framework.Test;


	public class SMIMETestSetup : TestSetup
	{
		private CommandMap originalMap = null;

		public SMIMETestSetup(Test test) : base(test)
		{
		}

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastleProvider());

			MailcapCommandMap _mailcap = (MailcapCommandMap)CommandMap.getDefaultCommandMap();

			_mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			_mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			_mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			_mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			_mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			originalMap = CommandMap.getDefaultCommandMap();
			CommandMap.setDefaultCommandMap(_mailcap);
		}

		public virtual void tearDown()
		{
			CommandMap.setDefaultCommandMap(originalMap);
			originalMap = null;
			Security.removeProvider("BC");
		}


	}

}