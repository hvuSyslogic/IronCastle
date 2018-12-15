using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	public sealed class Times
	{
		public static long nanoTime()
		{
			return JavaSystem.nanoTime();
		}
	}

}