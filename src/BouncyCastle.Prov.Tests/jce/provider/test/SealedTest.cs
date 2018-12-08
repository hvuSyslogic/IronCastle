using System;

namespace org.bouncycastle.jce.provider.test
{


	using SimpleTestResult = org.bouncycastle.util.test.SimpleTestResult;
	using Test = org.bouncycastle.util.test.Test;
	using TestResult = org.bouncycastle.util.test.TestResult;

	public class SealedTest : Test
	{
		internal const string provider = "BC";

		public virtual string getName()
		{
			return "SealedObject";
		}

		public virtual TestResult perform()
		{
			try
			{
				KeyGenerator keyGen = KeyGenerator.getInstance("DES", provider);
				Key key = keyGen.generateKey();
				Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding", provider);

				c.init(Cipher.ENCRYPT_MODE, key);
				string @object = "Hello world";
				SealedObject so = new SealedObject(@object, c);
				c.init(Cipher.DECRYPT_MODE, key);

				object o = so.getObject(c);
				if (!o.Equals(@object))
				{
					return new SimpleTestResult(false, "Result object 1 not equal" + "orig: " + @object + " res: " + o);
				}

				o = so.getObject(key);
				if (!o.Equals(@object))
				{
					return new SimpleTestResult(false, "Result object 2 not equal" + "orig: " + @object + " res: " + o);
				}

				o = so.getObject(key, provider);
				if (!o.Equals(@object))
				{
					return new SimpleTestResult(false, "Result object 3 not equal" + "orig: " + @object + " res: " + o);
				}

				return new SimpleTestResult(true, getName() + ": Okay");
			}
			catch (Exception e)
			{
				return new SimpleTestResult(false, getName() + ": failed excpetion - " + e.ToString(), e);
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			Test test = new SealedTest();
			TestResult result = test.perform();

			JavaSystem.@out.println(result.ToString());
		}
	}


}