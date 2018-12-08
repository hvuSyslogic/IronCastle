namespace org.bouncycastle.crypto.test
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public abstract class CipherTest : SimpleTest
	{
		private SimpleTest[] _tests;
		private BlockCipher _engine;
		private KeyParameter _validKey;

	//    protected CipherTest(
	//        SimpleTest[]  tests)
	//    {
	//        _tests = tests;
	//    }

		public CipherTest(SimpleTest[] tests, BlockCipher engine, KeyParameter validKey)
		{
			_tests = tests;
			_engine = engine;
			_validKey = validKey;
		}

		public override abstract string getName();

		public override void performTest()
		{
			for (int i = 0; i != _tests.Length; i++)
			{
				_tests[i].performTest();
			}

			if (_engine != null)
			{
				//
				// state tests
				//
				byte[] buf = new byte[128];

				try
				{
					_engine.processBlock(buf, 0, buf, 0);

					fail("failed initialisation check");
				}
				catch (IllegalStateException)
				{
					// expected 
				}

				bufferSizeCheck((_engine));
			}
		}

		private void bufferSizeCheck(BlockCipher engine)
		{
			byte[] correctBuf = new byte[engine.getBlockSize()];
			byte[] shortBuf = new byte[correctBuf.Length / 2];

			engine.init(true, _validKey);

			try
			{
				engine.processBlock(shortBuf, 0, correctBuf, 0);

				fail("failed short input check");
			}
			catch (DataLengthException)
			{
				// expected 
			}

			try
			{
				engine.processBlock(correctBuf, 0, shortBuf, 0);

				fail("failed short output check");
			}
			catch (DataLengthException)
			{
				// expected 
			}

			engine.init(false, _validKey);

			try
			{
				engine.processBlock(shortBuf, 0, correctBuf, 0);

				fail("failed short input check");
			}
			catch (DataLengthException)
			{
				// expected 
			}

			try
			{
				engine.processBlock(correctBuf, 0, shortBuf, 0);

				fail("failed short output check");
			}
			catch (DataLengthException)
			{
				// expected 
			}
		}
	}

}