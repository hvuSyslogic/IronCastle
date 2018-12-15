using System;
using org.bouncycastle.Port;

namespace org.bouncycastle.util.test
{

	public abstract class SimpleTest : Test
	{
		public abstract string getName();

		private TestResult success()
		{
			return SimpleTestResult.successful(this, "Okay");
		}

		public virtual void fail(string message)
		{
			throw new TestFailedException(SimpleTestResult.failed(this, message));
		}

		public virtual void isTrue(bool value)
		{
			if (!value)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
			}
		}

		public virtual void isTrue(string message, bool value)
		{
			if (!value)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}
		}

		public virtual void isEquals(object a, object b)
		{
			if (!a.Equals(b))
			{
				throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
			}
		}

		public virtual void isEquals(int a, int b)
		{
			if (a != b)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
			}
		}

		public virtual void isEquals(long a, long b)
		{
			if (a != b)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, "no message"));
			}
		}

		public virtual void isEquals(string message, bool a, bool b)
		{
			if (a != b)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}
		}

		public virtual void isEquals(string message, long a, long b)
		{
			if (a != b)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}
		}

		public virtual void isEquals(string message, object a, object b)
		{
			if (a == null && b == null)
			{
				return;
			}
			else if (a == null)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}
			else if (b == null)
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}

			if (!a.Equals(b))
			{
				throw new TestFailedException(SimpleTestResult.failed(this, message));
			}
		}

		public virtual bool areEqual(byte[][] left, byte[][] right)
		{
			if (left == null && right == null)
			{
				return true;
			}
			else if (left == null || right == null)
			{
				return false;
			}

			if (left.Length != right.Length)
			{
				return false;
			}

			for (int t = 0; t < left.Length; t++)
			{
				if (areEqual(left[t], right[t]))
				{
					continue;
				}
				return false;
			}

			return true;
		}


		public virtual void fail(string message, Exception throwable)
		{
			throw new TestFailedException(SimpleTestResult.failed(this, message, throwable));
		}

		public virtual void fail(string message, object expected, object found)
		{
			throw new TestFailedException(SimpleTestResult.failed(this, message, expected, found));
		}

		public virtual bool areEqual(byte[] a, byte[] b)
		{
			return Arrays.areEqual(a, b);
		}

		public virtual TestResult perform()
		{
			try
			{
				performTest();
				return success();
			}
			catch (TestFailedException e)
			{
				return e.getResult();
			}
			catch (Exception e)
			{
				return SimpleTestResult.failed(this, "Exception: " + e, e);
			}
		}

		protected internal static void runTest(Test test)
		{
			runTest(test, JavaSystem.@out);
		}

		protected internal static void runTest(Test test, PrintStream @out)
		{
			TestResult result = test.perform();

			@out.println(result.ToString());
			if (result.getException() != null)
			{
				result.getException().printStackTrace(@out);
			}
		}

		public abstract void performTest();
	}

}