using System;

namespace org.bouncycastle.i18n.test
{
	using TestCase = junit.framework.TestCase;
	using HTMLFilter = org.bouncycastle.i18n.filter.HTMLFilter;
	using TrustedInput = org.bouncycastle.i18n.filter.TrustedInput;
	using Hex = org.bouncycastle.util.encoders.Hex;


	public class LocalizedMessageTest : TestCase
	{

		private const string TEST_RESOURCE = "org.bouncycastle.i18n.test.I18nTestMessages";
		private const string UTF8_TEST_RESOURCE = "org.bouncycastle.i18n.test.I18nUTF8TestMessages";

		/*
		 * test message id's
		 */
		private const string timeTestId = "time";
		private const string argsTestId = "arguments";
		private const string localeTestId = "hello";
		private const string missingTestId = "missing";
		private const string filterTestId = "filter";
		private const string utf8TestId = "utf8";

		/*
		 * Test method for 'org.bouncycastle.i18n.LocalizedMessage.getEntry(String,
		 * Locale, TimeZone)'
		 */
		public virtual void testGetEntry()
		{
			LocalizedMessage msg;

			// test different locales
			msg = new LocalizedMessage(TEST_RESOURCE, localeTestId);
			assertEquals("Hello world.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));
			assertEquals("Hallo Welt.", msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));

			// test arguments
			object[] args = new object[] {"Nobody"};
			msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
			assertEquals("My name is Nobody.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));
			assertEquals("Mein Name ist Nobody.", msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));

			// test timezones
			// test date 17. Aug. 13:12:00 GMT
			DateTime testDate = new DateTime(1155820320000l);
			args = new object[] {new TrustedInput(testDate)};
			msg = new LocalizedMessage(TEST_RESOURCE, timeTestId, args);
			assertEquals("It's 1:12:00 PM GMT at Aug 17, 2006.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getTimeZone("GMT")));
			// NOTE: Older JDKs appear to use '.' as the time separator for German locale
			assertEquals("Es ist 13:12 Uhr GMT am 17.08.2006.", msg.getEntry("text", Locale.GERMAN, TimeZone.getTimeZone("GMT")).Replace("13.12", "13:12"));

			// test time with filter
			args = new object[] {new TrustedInput(testDate)};
			msg = new LocalizedMessage(TEST_RESOURCE, timeTestId, args);
			msg.setFilter(new HTMLFilter());
			assertEquals("It's 1:12:00 PM GMT at Aug 17, 2006.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getTimeZone("GMT")));
			// NOTE: Older JDKs appear to use '.' as the time separator for German locale
			assertEquals("Es ist 13:12 Uhr GMT am 17.08.2006.", msg.getEntry("text", Locale.GERMAN, TimeZone.getTimeZone("GMT")).Replace("13.12", "13:12"));

			// test number
			args = new object[] {new TrustedInput(new float?(0.2))};
			msg = new LocalizedMessage(TEST_RESOURCE, "number", args);
			assertEquals("20%", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));

			// test filters
			string untrusted = "<script>doBadThings()</script>";
			args = new object[] {untrusted};
			msg = new LocalizedMessage(TEST_RESOURCE,filterTestId,args);
			msg.setFilter(new HTMLFilter());
			assertEquals("The following part should contain no HTML tags: " + "&#60script&#62doBadThings&#40&#41&#60/script&#62", msg.getEntry("text",Locale.ENGLISH, TimeZone.getDefault()));

			// test missing entry
			msg = new LocalizedMessage(TEST_RESOURCE, missingTestId);
			try
			{
				string text = msg.getEntry("text", Locale.UK, TimeZone.getDefault());
				fail();
			}
			catch (MissingEntryException)
			{
	//            JavaSystem.@out.println(e.getDebugMsg());
			}

			// test missing entry
			try
			{
				URLClassLoader cl = URLClassLoader.newInstance(new URL[] {new URL("file:///nonexistent/")});
				msg = new LocalizedMessage(TEST_RESOURCE, missingTestId);
				msg.setClassLoader(cl);
				try
				{
					string text = msg.getEntry("text", Locale.UK, TimeZone.getDefault());
					fail();
				}
				catch (MissingEntryException)
				{
	//                JavaSystem.@out.println(e.getDebugMsg());
				}
			}
			catch (MalformedURLException)
			{

			}

			// test utf8
			try
			{
	//            String expectedUtf8 = "some umlauts äöüèéà";
				string expectedUtf8 = StringHelper.NewString(Hex.decode("736f6d6520756d6c6175747320c3a4c3b6c3bcc3a8c3a9c3a0"), "UTF-8");
				msg = new LocalizedMessage(UTF8_TEST_RESOURCE, utf8TestId, "UTF-8");
				assertEquals(expectedUtf8, msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));
			}
			catch (UnsupportedEncodingException)
			{

			}

		}

		public virtual void testLocalizedArgs()
		{
			LocaleString ls = new LocaleString(TEST_RESOURCE, "name");

			// without filter
			object[] args = new object[] {ls};
			LocalizedMessage msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
			assertEquals("My name is John.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));
			assertEquals("Mein Name ist Hans.", msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));

			// with filter
			msg.setFilter(new HTMLFilter());
			assertEquals("My name is John.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));
			assertEquals("Mein Name ist Hans.", msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));

			// add extra args
			LocaleString lsExtra = new LocaleString(TEST_RESOURCE, "hello.text");
			msg.setExtraArguments(new object[] {" ", lsExtra});
			assertEquals("My name is John. Hello world.", msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault()));
			assertEquals("Mein Name ist Hans. Hallo Welt.", msg.getEntry("text", Locale.GERMAN, TimeZone.getDefault()));

			// missing localized arg
			try
			{
				ls = new LocaleString(TEST_RESOURCE, "noname");
				args = new object[] {ls};
				msg = new LocalizedMessage(TEST_RESOURCE, argsTestId, args);
				msg.getEntry("text", Locale.ENGLISH, TimeZone.getDefault());
				fail();
			}
			catch (MissingEntryException e)
			{
				assertEquals("Can't find entry noname in resource file org.bouncycastle.i18n.test.I18nTestMessages.", e.Message);
			}
		}

	}

}