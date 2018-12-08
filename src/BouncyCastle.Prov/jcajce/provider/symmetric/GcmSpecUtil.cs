using System;

namespace org.bouncycastle.jcajce.provider.symmetric
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using GCMParameters = org.bouncycastle.asn1.cms.GCMParameters;
	using ClassUtil = org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
	using Integers = org.bouncycastle.util.Integers;

	public class GcmSpecUtil
	{
		internal static readonly Class gcmSpecClass = ClassUtil.loadClass(typeof(GcmSpecUtil), "javax.crypto.spec.GCMParameterSpec");

		internal static bool gcmSpecExists()
		{
			return gcmSpecClass != null;
		}

		internal static bool isGcmSpec(AlgorithmParameterSpec paramSpec)
		{
			return gcmSpecClass != null && gcmSpecClass.isInstance(paramSpec);
		}

		internal static bool isGcmSpec(Class paramSpecClass)
		{
			return gcmSpecClass == paramSpecClass;
		}

		internal static AlgorithmParameterSpec extractGcmSpec(ASN1Primitive spec)
		{
			try
			{
				GCMParameters gcmParams = GCMParameters.getInstance(spec);
				Constructor constructor = gcmSpecClass.getConstructor(new Class[]{Integer.TYPE, typeof(byte[])});

				return (AlgorithmParameterSpec)constructor.newInstance(new object[] {Integers.valueOf(gcmParams.getIcvLen() * 8), gcmParams.getNonce()});
			}
			catch (NoSuchMethodException)
			{
				throw new InvalidParameterSpecException("No constructor found!"); // should never happen
			}
			catch (Exception e)
			{
				throw new InvalidParameterSpecException("Construction failed: " + e.Message); // should never happen
			}
		}

		internal static GCMParameters extractGcmParameters(AlgorithmParameterSpec paramSpec)
		{
			try
			{
				Method tLen = gcmSpecClass.getDeclaredMethod("getTLen", new Class[0]);
				Method iv = gcmSpecClass.getDeclaredMethod("getIV", new Class[0]);

				return new GCMParameters((byte[])iv.invoke(paramSpec, new object[0]), ((int?)tLen.invoke(paramSpec, new object[0])).Value / 8);
			}
			catch (Exception)
			{
				throw new InvalidParameterSpecException("Cannot process GCMParameterSpec");
			}
		}
	}

}