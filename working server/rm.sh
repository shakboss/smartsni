sudo systemctl stop sni                                                                                                                                                    
     sudo systemctl disable sni                                                                                                                                                 
     sudo rm /etc/systemd/system/sni.service                                                                                                                                    
     sudo systemctl daemon-reload                                                                                                                                               
     sudo rm -rf /opt/smartSNI                                                                                                                                                  
     sudo userdel smart-sni 2>/dev/null                                                                                                                                         
     sudo rm -f /etc/letsencrypt/renewal/home.shaktt.xyz.conf                                                                                                                   
     crontab -l 2>/dev/null | grep -v "certbot renew" | crontab - 2>/dev/null                                                                                                   
     echo "Done. SmartSNI removed." 
