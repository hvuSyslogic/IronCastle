using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

			
	/// <summary>
	/// generate suitable parameters for GOST3410.
	/// </summary>
	public class GOST3410ParametersGenerator
	{
		private int size;
		private int typeproc;
		private SecureRandom init_random;

		private static readonly BigInteger ONE = BigInteger.valueOf(1);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		/// <summary>
		/// initialise the key generator.
		/// </summary>
		/// <param name="size"> size of the key </param>
		/// <param name="typeproc"> type procedure A,B = 1;  A',B' - else </param>
		/// <param name="random"> random byte source. </param>
		public virtual void init(int size, int typeproc, SecureRandom random)
		{
			this.size = size;
			this.typeproc = typeproc;
			this.init_random = random;
		}

		//Procedure A
		private int procedure_A(int x0, int c, BigInteger[] pq, int size)
		{
			//Verify and perform condition: 0<x<2^16; 0<c<2^16; c - odd.
			while (x0 < 0 || x0>65536)
			{
				x0 = init_random.nextInt() / 32768;
			}

			while ((c < 0 || c>65536) || (c / 2 == 0))
			{
				c = init_random.nextInt() / 32768 + 1;
			}

			BigInteger C = new BigInteger(Convert.ToString(c));
			BigInteger constA16 = new BigInteger("19381");

			//step1
			BigInteger[] y = new BigInteger[1]; // begin length = 1
			y[0] = new BigInteger(Convert.ToString(x0));

			//step 2
			int[] t = new int[1]; // t - orders; begin length = 1
			t[0] = size;
			int s = 0;
			for (int i = 0; t[i] >= 17; i++)
			{
				// extension array t
				int[] tmp_t = new int[t.Length + 1]; ///////////////
				JavaSystem.arraycopy(t,0,tmp_t,0,t.Length); //  extension
				t = new int[tmp_t.Length]; //  array t
				JavaSystem.arraycopy(tmp_t, 0, t, 0, tmp_t.Length); ///////////////

				t[i + 1] = t[i] / 2;
				s = i + 1;
			}

			//step3
			BigInteger[] p = new BigInteger[s + 1];
			p[s] = new BigInteger("8003",16); //set min prime number length 16 bit

			int m = s - 1; //step4

			for (int i = 0; i < s; i++)
			{
				int rm = t[m] / 16; //step5

		 for (;;)
		 {
					//step 6
					BigInteger[] tmp_y = new BigInteger[y.Length]; ////////////////
					JavaSystem.arraycopy(y,0,tmp_y,0,y.Length); //  extension
					y = new BigInteger[rm + 1]; //  array y
					JavaSystem.arraycopy(tmp_y,0,y,0,tmp_y.Length); ////////////////

					for (int j = 0; j < rm; j++)
					{
						y[j + 1] = (y[j].multiply(constA16).add(C)).mod(TWO.pow(16));
					}

					//step 7
					BigInteger Ym = new BigInteger("0");
					for (int j = 0; j < rm; j++)
					{
						Ym = Ym.add(y[j].multiply(TWO.pow(16 * j)));
					}

					y[0] = y[rm]; //step 8

					//step 9
					BigInteger N = TWO.pow(t[m] - 1).divide(p[m + 1]).add((TWO.pow(t[m] - 1).multiply(Ym)).divide(p[m + 1].multiply(TWO.pow(16 * rm))));

					if (N.mod(TWO).compareTo(ONE) == 0)
					{
						N = N.add(ONE);
					}

					int k = 0; //step 10

			for (;;)
			{
						//step 11
						p[m] = p[m + 1].multiply(N.add(BigInteger.valueOf(k))).add(ONE);

						if (p[m].compareTo(TWO.pow(t[m])) == 1)
						{
							goto step6Continue; //step 12
						}

						//step13
						if ((TWO.modPow(p[m + 1].multiply(N.add(BigInteger.valueOf(k))),p[m]).compareTo(ONE) == 0) && (TWO.modPow(N.add(BigInteger.valueOf(k)),p[m]).compareTo(ONE) != 0))
						{
							m -= 1;
							break;
						}
						else
						{
							k += 2;
							goto step11Continue;
						}
				step11Continue:;
			}
			step11Break:

					if (m >= 0)
					{
						break; //step 14
					}
					else
					{
						pq[0] = p[0];
						pq[1] = p[1];
						return y[0].intValue(); //return for procedure B step 2
					}
			 step6Continue:;
		 }
		 step6Break:;
			}
			return y[0].intValue();
		}

		//Procedure A'
		private long procedure_Aa(long x0, long c, BigInteger[] pq, int size)
		{
			//Verify and perform condition: 0<x<2^32; 0<c<2^32; c - odd.
			while (x0 < 0 || x0>4294967296L)
			{
				x0 = init_random.nextInt() * 2;
			}

			while ((c < 0 || c>4294967296L) || (c / 2 == 0))
			{
				c = init_random.nextInt() * 2 + 1;
			}

			BigInteger C = new BigInteger(Convert.ToString(c));
			BigInteger constA32 = new BigInteger("97781173");

			//step1
			BigInteger[] y = new BigInteger[1]; // begin length = 1
			y[0] = new BigInteger(Convert.ToString(x0));

			//step 2
			int[] t = new int[1]; // t - orders; begin length = 1
			t[0] = size;
			int s = 0;
			for (int i = 0; t[i] >= 33; i++)
			{
				// extension array t
				int[] tmp_t = new int[t.Length + 1]; ///////////////
				JavaSystem.arraycopy(t,0,tmp_t,0,t.Length); //  extension
				t = new int[tmp_t.Length]; //  array t
				JavaSystem.arraycopy(tmp_t, 0, t, 0, tmp_t.Length); ///////////////

				t[i + 1] = t[i] / 2;
				s = i + 1;
			}

			//step3
			BigInteger[] p = new BigInteger[s + 1];
			p[s] = new BigInteger("8000000B",16); //set min prime number length 32 bit

			int m = s - 1; //step4

			for (int i = 0; i < s; i++)
			{
				int rm = t[m] / 32; //step5

		 for (;;)
		 {
					//step 6
					BigInteger[] tmp_y = new BigInteger[y.Length]; ////////////////
					JavaSystem.arraycopy(y,0,tmp_y,0,y.Length); //  extension
					y = new BigInteger[rm + 1]; //  array y
					JavaSystem.arraycopy(tmp_y,0,y,0,tmp_y.Length); ////////////////

					for (int j = 0; j < rm; j++)
					{
						y[j + 1] = (y[j].multiply(constA32).add(C)).mod(TWO.pow(32));
					}

					//step 7
					BigInteger Ym = new BigInteger("0");
					for (int j = 0; j < rm; j++)
					{
						Ym = Ym.add(y[j].multiply(TWO.pow(32 * j)));
					}

					y[0] = y[rm]; //step 8

					//step 9
					BigInteger N = TWO.pow(t[m] - 1).divide(p[m + 1]).add((TWO.pow(t[m] - 1).multiply(Ym)).divide(p[m + 1].multiply(TWO.pow(32 * rm))));

					if (N.mod(TWO).compareTo(ONE) == 0)
					{
						N = N.add(ONE);
					}

					int k = 0; //step 10

			for (;;)
			{
						//step 11
						p[m] = p[m + 1].multiply(N.add(BigInteger.valueOf(k))).add(ONE);

						if (p[m].compareTo(TWO.pow(t[m])) == 1)
						{
							goto step6Continue; //step 12
						}

						//step13
						if ((TWO.modPow(p[m + 1].multiply(N.add(BigInteger.valueOf(k))),p[m]).compareTo(ONE) == 0) && (TWO.modPow(N.add(BigInteger.valueOf(k)),p[m]).compareTo(ONE) != 0))
						{
							m -= 1;
							break;
						}
						else
						{
							k += 2;
							goto step11Continue;
						}
				step11Continue:;
			}
			step11Break:

					if (m >= 0)
					{
						break; //step 14
					}
					else
					{
						pq[0] = p[0];
						pq[1] = p[1];
						return y[0].longValue(); //return for procedure B' step 2
					}
			 step6Continue:;
		 }
		 step6Break:;
			}
			return y[0].longValue();
		}

		//Procedure B
		private void procedure_B(int x0, int c, BigInteger[] pq)
		{
			//Verify and perform condition: 0<x<2^16; 0<c<2^16; c - odd.
			while (x0 < 0 || x0>65536)
			{
				x0 = init_random.nextInt() / 32768;
			}

			while ((c < 0 || c>65536) || (c / 2 == 0))
			{
				c = init_random.nextInt() / 32768 + 1;
			}

			BigInteger[] qp = new BigInteger[2];
			BigInteger q = null, Q = null, p = null;
			BigInteger C = new BigInteger(Convert.ToString(c));
			BigInteger constA16 = new BigInteger("19381");

			//step1
			x0 = procedure_A(x0, c, qp, 256);
			q = qp[0];

			//step2
			x0 = procedure_A(x0, c, qp, 512);
			Q = qp[0];

			BigInteger[] y = new BigInteger[65];
			y[0] = new BigInteger(Convert.ToString(x0));

			int tp = 1024;

	 for (;;)
	 {
				//step 3
				for (int j = 0; j < 64; j++)
				{
					y[j + 1] = (y[j].multiply(constA16).add(C)).mod(TWO.pow(16));
				}

				//step 4
				BigInteger Y = new BigInteger("0");

				for (int j = 0; j < 64; j++)
				{
					Y = Y.add(y[j].multiply(TWO.pow(16 * j)));
				}

				y[0] = y[64]; //step 5

				//step 6
				BigInteger N = TWO.pow(tp - 1).divide(q.multiply(Q)).add((TWO.pow(tp - 1).multiply(Y)).divide(q.multiply(Q).multiply(TWO.pow(1024))));

				if (N.mod(TWO).compareTo(ONE) == 0)
				{
					N = N.add(ONE);
				}

				int k = 0; //step 7

		 for (;;)
		 {
					//step 11
					p = q.multiply(Q).multiply(N.add(BigInteger.valueOf(k))).add(ONE);

					if (p.compareTo(TWO.pow(tp)) == 1)
					{
						goto step3Continue; //step 9
					}

					//step10
					if ((TWO.modPow(q.multiply(Q).multiply(N.add(BigInteger.valueOf(k))),p).compareTo(ONE) == 0) && (TWO.modPow(q.multiply(N.add(BigInteger.valueOf(k))),p).compareTo(ONE) != 0))
					{
						pq[0] = p;
						pq[1] = q;
						return;
					}
					else
					{
						k += 2;
						goto step8Continue;
					}
			 step8Continue:;
		 }
		 step3Continue:;
	 }
		}

		//Procedure B'
		private void procedure_Bb(long x0, long c, BigInteger[] pq)
		{
			//Verify and perform condition: 0<x<2^32; 0<c<2^32; c - odd.
			while (x0 < 0 || x0>4294967296L)
			{
				x0 = init_random.nextInt() * 2;
			}

			while ((c < 0 || c>4294967296L) || (c / 2 == 0))
			{
				c = init_random.nextInt() * 2 + 1;
			}

			BigInteger[] qp = new BigInteger[2];
			BigInteger q = null, Q = null, p = null;
			BigInteger C = new BigInteger(Convert.ToString(c));
			BigInteger constA32 = new BigInteger("97781173");

			//step1
			x0 = procedure_Aa(x0, c, qp, 256);
			q = qp[0];

			//step2
			x0 = procedure_Aa(x0, c, qp, 512);
			Q = qp[0];

			BigInteger[] y = new BigInteger[33];
			y[0] = new BigInteger(Convert.ToString(x0));

			int tp = 1024;

	 for (;;)
	 {
				//step 3
				for (int j = 0; j < 32; j++)
				{
					y[j + 1] = (y[j].multiply(constA32).add(C)).mod(TWO.pow(32));
				}

				//step 4
				BigInteger Y = new BigInteger("0");
				for (int j = 0; j < 32; j++)
				{
					Y = Y.add(y[j].multiply(TWO.pow(32 * j)));
				}

				y[0] = y[32]; //step 5

				//step 6
				BigInteger N = TWO.pow(tp - 1).divide(q.multiply(Q)).add((TWO.pow(tp - 1).multiply(Y)).divide(q.multiply(Q).multiply(TWO.pow(1024))));

				if (N.mod(TWO).compareTo(ONE) == 0)
				{
					N = N.add(ONE);
				}

				int k = 0; //step 7

		 for (;;)
		 {
					//step 11
					p = q.multiply(Q).multiply(N.add(BigInteger.valueOf(k))).add(ONE);

					if (p.compareTo(TWO.pow(tp)) == 1)
					{
						goto step3Continue; //step 9
					}

					//step10
					if ((TWO.modPow(q.multiply(Q).multiply(N.add(BigInteger.valueOf(k))),p).compareTo(ONE) == 0) && (TWO.modPow(q.multiply(N.add(BigInteger.valueOf(k))),p).compareTo(ONE) != 0))
					{
						pq[0] = p;
						pq[1] = q;
						return;
					}
					else
					{
						k += 2;
						goto step8Continue;
					}
			 step8Continue:;
		 }
		 step3Continue:;
	 }
		}


		/*
		 * Procedure C
		 * procedure generates the a value from the given p,q,
		 * returning the a value.
		 */
		private BigInteger procedure_C(BigInteger p, BigInteger q)
		{
			BigInteger pSub1 = p.subtract(ONE);
			BigInteger pSub1DivQ = pSub1.divide(q);
			int length = p.bitLength();

			for (;;)
			{
				BigInteger d = BigIntegers.createRandomBigInteger(length, init_random);

				// 1 < d < p-1
				if (d.compareTo(ONE) > 0 && d.compareTo(pSub1) < 0)
				{
					BigInteger a = d.modPow(pSub1DivQ, p);

					if (a.compareTo(ONE) != 0)
					{
						return a;
					}
				}
			}
		}

		/// <summary>
		/// which generates the p , q and a values from the given parameters,
		/// returning the GOST3410Parameters object.
		/// </summary>
		/// <returns> a generated GOST3410 parameters object. </returns>
		public virtual GOST3410Parameters generateParameters()
		{
			BigInteger[] pq = new BigInteger[2];
			BigInteger q = null, p = null, a = null;

			int x0, c;
			long x0L, cL;

			if (typeproc == 1)
			{
				x0 = init_random.nextInt();
				c = init_random.nextInt();

				switch (size)
				{
				case 512:
					procedure_A(x0, c, pq, 512);
					break;
				case 1024:
					procedure_B(x0, c, pq);
					break;
				default:
					throw new IllegalArgumentException("Ooops! key size 512 or 1024 bit.");
				}
				p = pq[0];
				q = pq[1];
				a = procedure_C(p, q);
				//JavaSystem.@out.println("p:"+p.toString(16)+"\n"+"q:"+q.toString(16)+"\n"+"a:"+a.toString(16));
				//JavaSystem.@out.println("p:"+p+"\n"+"q:"+q+"\n"+"a:"+a);
				return new GOST3410Parameters(p, q, a, new GOST3410ValidationParameters(x0, c));
			}
			else
			{
				x0L = init_random.nextLong();
				cL = init_random.nextLong();

				switch (size)
				{
				case 512:
					procedure_Aa(x0L, cL, pq, 512);
					break;
				case 1024:
					procedure_Bb(x0L, cL, pq);
					break;
				default:
					throw new IllegalStateException("Ooops! key size 512 or 1024 bit.");
				}
				p = pq[0];
				q = pq[1];
				a = procedure_C(p, q);
				//JavaSystem.@out.println("p:"+p.toString(16)+"\n"+"q:"+q.toString(16)+"\n"+"a:"+a.toString(16));
				//JavaSystem.@out.println("p:"+p+"\n"+"q:"+q+"\n"+"a:"+a);
				return new GOST3410Parameters(p, q, a, new GOST3410ValidationParameters(x0L, cL));
			}
		}
	}

}