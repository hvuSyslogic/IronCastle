using System;

namespace org.bouncycastle.util.test
{
	public interface TestResult
	{
		bool isSuccessful();

		Exception getException();

		string ToString();
	}

}