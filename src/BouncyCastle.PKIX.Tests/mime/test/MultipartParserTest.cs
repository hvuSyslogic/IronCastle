using org.bouncycastle.mime.test;

using System;

namespace org.bouncycastle.mime.test
{

	using TestCase = junit.framework.TestCase;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSException = org.bouncycastle.cms.CMSException;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using JcaSimpleSignerInfoVerifierBuilder = org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using SMimeParserListener = org.bouncycastle.mime.smime.SMimeParserListener;
	using SMimeParserProvider = org.bouncycastle.mime.smime.SMimeParserProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using BcDigestCalculatorProvider = org.bouncycastle.@operator.bc.BcDigestCalculatorProvider;
	using Store = org.bouncycastle.util.Store;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;

	public class MultipartParserTest : TestCase
	{

		public virtual void setUp()
		{
			if (Security.getProvider("BC") == null)
			{
				Security.addProvider(new BouncyCastleProvider());
			}
		}


		/// <summary>
		/// Parse content header good.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testParseContentTypeHeader_wellformed()
		{
			string value = "multipart/alternative;\n" +
				@" boundary=""Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84""";

			ArrayList<string> values = new ArrayList<string>();
			values.add("Content-type: " + value);

			Headers headers = new Headers(values, value);
			TestCase.assertEquals("multipart/alternative", headers.getContentType());
			Map<string, string> fieldValues = headers.getContentTypeAttributes();
			TestCase.assertEquals(1, fieldValues.size());
			TestCase.assertEquals(@"{boundary=""Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84""}", fieldValues.ToString());
		}


		/// <summary>
		/// Parse content header good.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testParseContentTypeHeader_wellformed_multi()
		{
			string value = "multipart/signed;\n" +
				@" boundary=""Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84""; micalg=""SHA1""";

			ArrayList<string> values = new ArrayList<string>();
			values.add("Content-type: " + value);

			Headers headers = new Headers(values, value);
			TestCase.assertEquals("multipart/signed", headers.getContentType());
			Map<string, string> fieldValues = headers.getContentTypeAttributes();
			TestCase.assertEquals(2, fieldValues.size());
			TestCase.assertEquals(@"{boundary=""Apple-Mail=_8B1F6ECB-9629-424B-B871-1357CCDBCC84"", micalg=""SHA1""}", fieldValues.ToString());
		}


		/// <summary>
		/// Parse content header good.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testParseContentTypeHeader_broken()
		{

			// Verify limit checking

			string value = "multipart/alternative;\n" +
				@" boundary=""cats""; micalg=";

			ArrayList<string> values = new ArrayList<string>();
			values.add("Content-type: " + value);

			Headers headers = new Headers(values, value);
			TestCase.assertEquals("multipart/alternative", headers.getContentType());
			Map<string, string> fieldValues = headers.getContentTypeAttributes();
			TestCase.assertEquals(2, fieldValues.size());
			TestCase.assertEquals(@"{boundary=""cats"", micalg=}", fieldValues.ToString());
		}

		/// <summary>
		/// Parse content header good.
		/// </summary>
		/// <exception cref="Exception"> </exception>
		public virtual void testParseContentTypeHeader_empty_micalg()
		{

			// Verify limit checking

			string value = "multipart/alternative;\n" +
				@" boundary=""cats""; micalg=""""";

			ArrayList<string> values = new ArrayList<string>();
			values.add("Content-type: " + value);

			Headers headers = new Headers(values, value);
			TestCase.assertEquals("multipart/alternative", headers.getContentType());
			Map<string, string> fieldValues = headers.getContentTypeAttributes();
			TestCase.assertEquals(2, fieldValues.size());
			TestCase.assertEquals(@"{boundary=""cats"", micalg=""""}", headers.getContentTypeAttributes().ToString());
		}

		public virtual void testSignedMultipart()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.ArrayList<Object> results = new java.util.ArrayList<Object>();
			ArrayList<object> results = new ArrayList<object>();

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final TestDoneFlag dataParsed = new TestDoneFlag();
			TestDoneFlag dataParsed = new TestDoneFlag();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(this.GetType().getResourceAsStream("quotable.message"));

			p.parse(new SMimeParserListenerAnonymousInnerClass(this, results, dataParsed));

			assertTrue(dataParsed.isDone());
		}

		public class SMimeParserListenerAnonymousInnerClass : SMimeParserListener
		{
			private readonly MultipartParserTest outerInstance;

			private ArrayList<object> results;
			private TestDoneFlag dataParsed;

			public SMimeParserListenerAnonymousInnerClass(MultipartParserTest outerInstance, ArrayList<object> results, TestDoneFlag dataParsed)
			{
				this.outerInstance = outerInstance;
				this.results = results;
				this.dataParsed = dataParsed;
			}

			public override void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				Streams.pipeAll((InputStream)inputStream, bos);
				results.add(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
				JavaSystem.@out.println(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
			}

			public override void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
			{
				Collection c = signers.getSigners();
				Iterator it = c.iterator();

				while (it.hasNext())
				{
					SignerInformation signer = (SignerInformation)it.next();
					Collection certCollection = certificates.getMatches(signer.getSID());

					Iterator certIt = certCollection.iterator();
					X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

					try
					{
						assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
					}
					catch (OperatorCreationException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
					catch (CertificateException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
				}

				dataParsed.markDone();
			}

		}

		public virtual void testInvalidSha256SignedMultipart()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.ArrayList<Object> results = new java.util.ArrayList<Object>();
			ArrayList<object> results = new ArrayList<object>();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(this.GetType().getResourceAsStream("3nnn_smime.eml"));

			p.parse(new SMimeParserListenerAnonymousInnerClass2(this, results));
		}

		public class SMimeParserListenerAnonymousInnerClass2 : SMimeParserListener
		{
			private readonly MultipartParserTest outerInstance;

			private ArrayList<object> results;

			public SMimeParserListenerAnonymousInnerClass2(MultipartParserTest outerInstance, ArrayList<object> results)
			{
				this.outerInstance = outerInstance;
				this.results = results;
			}

			public override void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				Streams.pipeAll((InputStream)inputStream, bos);
				results.add(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
				JavaSystem.@out.println(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
			}

			public override void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
			{
				Collection c = signers.getSigners();
				Iterator it = c.iterator();

				while (it.hasNext())
				{
					SignerInformation signer = (SignerInformation)it.next();
					Collection certCollection = certificates.getMatches(signer.getSID());

					Iterator certIt = certCollection.iterator();
					X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

					try
					{
						// in this case the signature is invalid
						assertEquals(false, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
					}
					catch (OperatorCreationException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
					catch (CertificateException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
				}
			}

		}

		public virtual void testEmbeddedMultipart()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.ArrayList<Object> results = new java.util.ArrayList<Object>();
			ArrayList<object> results = new ArrayList<object>();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(this.GetType().getResourceAsStream("embeddedmulti.message"));

			p.parse(new SMimeParserListenerAnonymousInnerClass3(this, results));
		}

		public class SMimeParserListenerAnonymousInnerClass3 : SMimeParserListener
		{
			private readonly MultipartParserTest outerInstance;

			private ArrayList<object> results;

			public SMimeParserListenerAnonymousInnerClass3(MultipartParserTest outerInstance, ArrayList<object> results)
			{
				this.outerInstance = outerInstance;
				this.results = results;
			}

			public override void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{
				ByteArrayOutputStream bos = new ByteArrayOutputStream();
				Streams.pipeAll((InputStream)inputStream, bos);
				results.add(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
				JavaSystem.@out.println(bos.ToString());
				JavaSystem.@out.println("#######################################################################");
			}

			public override void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
			{
				Collection c = signers.getSigners();
				Iterator it = c.iterator();

				while (it.hasNext())
				{
					SignerInformation signer = (SignerInformation)it.next();
					Collection certCollection = certificates.getMatches(signer.getSID());

					Iterator certIt = certCollection.iterator();
					X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

					try
					{
						assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
					}
					catch (OperatorCreationException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
					catch (CertificateException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
				}
			}

		}

		public virtual void testMultipartAlternative()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.ArrayList<Object> results = new java.util.ArrayList<Object>();
			ArrayList<object> results = new ArrayList<object>();

			MimeParserProvider provider = new SMimeParserProvider("7bit", new BcDigestCalculatorProvider());

			MimeParser p = provider.createParser(this.GetType().getResourceAsStream("multi-alternative.eml"));

			p.parse(new SMimeParserListenerAnonymousInnerClass4(this, results));
		}

		public class SMimeParserListenerAnonymousInnerClass4 : SMimeParserListener
		{
			private readonly MultipartParserTest outerInstance;

			private ArrayList<object> results;

			public SMimeParserListenerAnonymousInnerClass4(MultipartParserTest outerInstance, ArrayList<object> results)
			{
				this.outerInstance = outerInstance;
				this.results = results;
			}

			public override void content(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{

				MimeParser basicMimeParser = new BasicMimeParser(parserContext, headers, inputStream);

				basicMimeParser.parse(new MimeParserListenerAnonymousInnerClass(this, parserContext, headers, inputStream));
			}

			public class MimeParserListenerAnonymousInnerClass : MimeParserListener
			{
				private readonly SMimeParserListenerAnonymousInnerClass4 outerInstance;

				private MimeParserContext parserContext;
				private Headers headers;
				private InputStream inputStream;

				public MimeParserListenerAnonymousInnerClass(SMimeParserListenerAnonymousInnerClass4 outerInstance, MimeParserContext parserContext, Headers headers, InputStream inputStream)
				{
					this.outerInstance = outerInstance;
					this.parserContext = parserContext;
					this.headers = headers;
					this.inputStream = inputStream;
				}

				public MimeContext createContext(MimeParserContext parserContext, Headers headers)
				{
					return new ConstantMimeContext();
				}

				public void @object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
				{
					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					Streams.pipeAll((InputStream)inputStream, bos);
					outerInstance.results.add(bos.ToString());
					JavaSystem.@out.println("#######################################################################");
					JavaSystem.@out.println(bos.ToString());
					JavaSystem.@out.println("#######################################################################");
				}
			}

			public override void signedData(MimeParserContext parserContext, Headers headers, Store certificates, Store CRLs, Store attributeCertificates, SignerInformationStore signers)
			{
				Collection c = signers.getSigners();
				Iterator it = c.iterator();

				while (it.hasNext())
				{
					SignerInformation signer = (SignerInformation)it.next();
					Collection certCollection = certificates.getMatches(signer.getSID());

					Iterator certIt = certCollection.iterator();
					X509CertificateHolder certHolder = (X509CertificateHolder)certIt.next();

					try
					{
						assertEquals(true, signer.verify((new JcaSimpleSignerInfoVerifierBuilder()).setProvider("BC").build(certHolder)));
					}
					catch (OperatorCreationException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
					catch (CertificateException e)
					{
						Console.WriteLine(e.ToString());
						Console.Write(e.StackTrace);
					}
				}
			}

		}

		/// <summary>
		/// Happy path mime multipart test.
		/// </summary>
		/// <exception cref="IOException"> </exception>
		public virtual void testMimeMultipart()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final java.util.ArrayList<Object> results = new java.util.ArrayList<Object>();
			ArrayList<object> results = new ArrayList<object>();

			BasicMimeParser p = new BasicMimeParser(this.GetType().getResourceAsStream("simplemultipart.eml"));

			p.parse(new MimeParserListenerAnonymousInnerClass2(this, results));


			string[] expected = new string[]{"The cat sat on the mat\n" + "\n" + "Boo!\n" + "\n", @"<html><head><meta http-equiv=""Content-Type"" object=""text/html; charset=us-ascii""></head><object style=""word-wrap: break-word; -webkit-nbsp-mode: space; line-break: after-white-space;"" class=""""><meta http-equiv=""Content-Type"" object=""text/html; charset=us-ascii"" class=""""><div style=""word-wrap: break-word; -webkit-nbsp-mode: space; line-break: after-white-space;"" class="""">The cat sat on the mat<div class=""""><br class=""""></div><div class=""""><font size=""7"" class="""">Boo!</font></div><div class=""""><font size=""7"" class=""""><br class=""""></font></div><div class=""""><img src=""http://img2.thejournal.ie/inline/1162441/original/?width=630&amp;version=1162441"" alt=""Image result for cows"" class=""""></div></div></object></html>"};

			TestCase.assertEquals("Size same:", expected.Length, results.size());

			for (int t = 0; t < results.size(); t++)
			{
				TestCase.assertEquals("Part: " + t, expected[t], results.get(t));
			}

		}

		public class MimeParserListenerAnonymousInnerClass2 : MimeParserListener
		{
			private readonly MultipartParserTest outerInstance;

			private ArrayList<object> results;

			public MimeParserListenerAnonymousInnerClass2(MultipartParserTest outerInstance, ArrayList<object> results)
			{
				this.outerInstance = outerInstance;
				this.results = results;
			}

			public MimeContext createContext(MimeParserContext parserContext, Headers headers)
			{
				return new MimeMultipartContextAnonymousInnerClass(this, headers);
			}

			public class MimeMultipartContextAnonymousInnerClass : MimeMultipartContext
			{
				private readonly MimeParserListenerAnonymousInnerClass2 outerInstance;

				private Headers headers;

				public MimeMultipartContextAnonymousInnerClass(MimeParserListenerAnonymousInnerClass2 outerInstance, Headers headers)
				{
					this.outerInstance = outerInstance;
					this.headers = headers;
				}

				public InputStream applyContext(Headers headers, InputStream contentStream)
				{
					return contentStream;
				}

				public MimeContext createContext(int partNo)
				{
					return new MimeContextAnonymousInnerClass(this);
				}

				public class MimeContextAnonymousInnerClass : MimeContext
				{
					private readonly MimeMultipartContextAnonymousInnerClass outerInstance;

					public MimeContextAnonymousInnerClass(MimeMultipartContextAnonymousInnerClass outerInstance)
					{
						this.outerInstance = outerInstance;
					}

					public InputStream applyContext(Headers headers, InputStream contentStream)
					{
						return contentStream;
					}
				}
			}

			public void @object(MimeParserContext parserContext, Headers headers, InputStream inputStream)
			{
				results.add(Strings.fromByteArray(Streams.readAll(inputStream)));
			}
		}



	}

}