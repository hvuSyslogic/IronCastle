using org.bouncycastle.Port;

namespace org.bouncycastle.util.test
{
	public class TestFailedException : RuntimeException
	{
		private TestResult _result;

		public TestFailedException(TestResult result)
		{
			_result = result;
		}

		public virtual TestResult getResult()
		{
			return _result;
		}
	}

}