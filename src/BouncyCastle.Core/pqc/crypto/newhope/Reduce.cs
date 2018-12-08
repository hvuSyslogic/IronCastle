namespace org.bouncycastle.pqc.crypto.newhope
{
	public class Reduce
	{
		internal const int QInv = 12287; // -inverse_mod(p,2^18)
		internal const int RLog = 18;
		internal static readonly int RMask = (1 << RLog) - 1;

		internal static short montgomery(int a)
		{
			int u = a * QInv;
			u &= RMask;
			u *= Params.Q;
			u += a;
			return (short)((int)((uint)u >> RLog));
		}

		internal static short barrett(short a)
		{
			int t = a & 0xFFFF;
			int u = (int)((uint)(t * 5) >> 16);
			u *= Params.Q;
			return (short)(t - u);
		}
	}

}