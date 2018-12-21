/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.Management_files;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 *
 * @author Randyms
 */
public class File_Manager {
    
    //Este metodo se encargara de crear la ruta con extension de cifrado .crypt
    public static String getFileNameWithFileExtension(String name,byte [] typeFile){
        return name.replace(".crypt",getExtensionFile(typeFile));
    }
    //Este metodo se encargar de crear la ruta del archivo con su extencion original
    public static String getFileNameWithCryptExtension(String name,String extenxion){
         return name.replace(getExtensionFile(extenxion.getBytes()), ".crypt");
    }
    //Se encarga de generara el tipo de extencion del archivo apartir 
    //de un arreglo de byte
    public static String getExtensionFile(byte [] extension){
        String ext_file = new String(extension);
        StringBuilder builder = new StringBuilder();
        if(!ext_file.contains(".")){
            builder.append(".").append(ext_file);
        }else{
            builder.append(ext_file);
        }
        return builder.toString();
    }
    
    //Metodo general para la creacion de Files necesarios para la ejecucion del programa
    public static File getFile(Path file_path){
        if(!Files.exists(file_path)){
            try {
                Files.createFile(file_path);
            } catch (IOException ex) {
                Logger.getLogger(File_Manager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file_path.toFile();
    }
    
    //Se encarga primero de validar si el archivo existe y en caso que no lo creara
    public static File createFile(String path){
        Path ruta = Paths.get(path);
        if(!Files.exists(ruta)){
            try {
                Files.createFile(ruta);
            } catch (IOException ex) {
                Logger.getLogger(File_Manager.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return ruta.toFile();
        
    }
    
    //Metodo qeu se encargara de obtener el tipo de archivo apartir de la ruta
    //Especifica del archivo
    public static String getTypeFile(String archivo){
       String [] tipo = archivo.split(Pattern.quote("."));
       String requestVal = tipo[1];
        if(tipo[1].length() < 4){
            requestVal = getExtensionFile(tipo[1].getBytes());
        }
        return requestVal;
    }
    
}
