namespace org.bouncycastle.util.test
{
	public interface Test
	{
		string getName();

		TestResult perform();
	}

}