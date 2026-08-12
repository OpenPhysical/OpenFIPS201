package dev.mistial.tools.openfips201.nist;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Builds a tiny overlay for NIST 5.0.1 calls removed from current BouncyCastle. */
public final class NistCompatibilityPatcher {
  private static final String TAGGED_OBJECT = "org/bouncycastle/asn1/ASN1TaggedObject";
  private static final String ASN1_PRIMITIVE = "()Lorg/bouncycastle/asn1/ASN1Primitive;";

  private NistCompatibilityPatcher() {}

  public static void main(String[] args) throws Exception {
    if (args.length != 2) {
      throw new IllegalArgumentException("usage: NistCompatibilityPatcher INPUT_JAR OUTPUT_JAR");
    }
    File output = new File(args[1]);
    File parent = output.getParentFile();
    if (parent != null) parent.mkdirs();
    int patched = 0;
    try (JarFile input = new JarFile(args[0]);
        JarOutputStream result = new JarOutputStream(new FileOutputStream(output))) {
      Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        JarEntry entry = entries.nextElement();
        if (!entry.getName().endsWith(".class")) continue;
        byte[] original;
        try (InputStream stream = input.getInputStream(entry)) {
          original = readAll(stream);
        }
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);
        final boolean[] changed = {false};
        new ClassReader(original)
            .accept(
                new ClassVisitor(Opcodes.ASM9, writer) {
                  @Override
                  public MethodVisitor visitMethod(
                      int access,
                      String name,
                      String descriptor,
                      String signature,
                      String[] exceptions) {
                    MethodVisitor delegate =
                        super.visitMethod(access, name, descriptor, signature, exceptions);
                    return new MethodVisitor(Opcodes.ASM9, delegate) {
                      @Override
                      public void visitMethodInsn(
                          int opcode,
                          String owner,
                          String methodName,
                          String methodDescriptor,
                          boolean isInterface) {
                        if (opcode == Opcodes.INVOKEVIRTUAL
                            && TAGGED_OBJECT.equals(owner)
                            && "getObject".equals(methodName)
                            && ASN1_PRIMITIVE.equals(methodDescriptor)) {
                          methodName = "getExplicitBaseObject";
                          methodDescriptor = "()Lorg/bouncycastle/asn1/ASN1Object;";
                          changed[0] = true;
                        }
                        if ("org/bouncycastle/asn1/DERIA5String".equals(owner)) {
                          owner = "org/bouncycastle/asn1/ASN1IA5String";
                          methodDescriptor =
                              methodDescriptor.replace(
                                  "Lorg/bouncycastle/asn1/DERIA5String;",
                                  "Lorg/bouncycastle/asn1/ASN1IA5String;");
                          changed[0] = true;
                        }
                        super.visitMethodInsn(
                            opcode, owner, methodName, methodDescriptor, isInterface);
                      }
                    };
                  }
                },
                ClassReader.SKIP_FRAMES);
        if (changed[0]) {
          result.putNextEntry(new JarEntry(entry.getName()));
          result.write(writer.toByteArray());
          result.closeEntry();
          patched++;
        }
      }
    }
    if (patched == 0) {
      throw new IllegalStateException("NIST compatibility overlay patched no classes");
    }
    System.out.println("Patched " + patched + " NIST class(es) for current BouncyCastle");
  }

  private static byte[] readAll(InputStream input) throws Exception {
    java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int count;
    while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
    return output.toByteArray();
  }
}
