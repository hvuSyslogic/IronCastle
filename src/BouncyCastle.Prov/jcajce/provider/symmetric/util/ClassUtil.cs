using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{

	public class ClassUtil
	{
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static Class loadClass(Class sourceClass, final String className)
		public static Class loadClass(Class sourceClass, string className)
		{
			try
			{
				ClassLoader loader = sourceClass.getClassLoader();

				if (loader != null)
				{
					return loader.loadClass(className);
				}
				else
				{
					return (Class)AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(className));
				}
			}
			catch (ClassNotFoundException)
			{
				// ignore - maybe log?
			}

			return null;
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			private string className;

			public PrivilegedActionAnonymousInnerClass(string className)
			{
				this.className = className;
			}

			public object run()
			{
				try
				{
					return Class.forName(className);
				}
				catch (Exception)
				{
					// ignore - maybe log?
				}

				return null;
			}
		}
	}

}