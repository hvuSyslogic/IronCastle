using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util.test
{

	public class SimpleTestResult : TestResult
	{
		private static readonly string SEPARATOR = Strings.lineSeparator();

		private bool success;
		private string message;
		private Exception exception;

		public SimpleTestResult(bool success, string message)
		{
			this.success = success;
			this.message = message;
		}

		public SimpleTestResult(bool success, string message, Exception exception)
		{
			this.success = success;
			this.message = message;
			this.exception = exception;
		}

		public static TestResult successful(Test test, string message)
		{
			return new SimpleTestResult(true, test.getName() + ": " + message);
		}

		public static TestResult failed(Test test, string message)
		{
			return new SimpleTestResult(false, test.getName() + ": " + message);
		}

		public static TestResult failed(Test test, string message, Exception t)
		{
			return new SimpleTestResult(false, test.getName() + ": " + message, t);
		}

		public static TestResult failed(Test test, string message, object expected, object found)
		{
			return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
		}

		public static string failedMessage(string algorithm, string testName, string expected, string actual)
		{
			StringBuffer sb = new StringBuffer(algorithm);
			sb.append(" failing ").append(testName);
			sb.append(SEPARATOR).append("    expected: ").append(expected);
			sb.append(SEPARATOR).append("    got     : ").append(actual);

			return sb.ToString();
		}

		public virtual bool isSuccessful()
		{
			return success;
		}

		public override string ToString()
		{
			return message;
		}

		public virtual Exception getException()
		{
			return exception;
		}
	}

}