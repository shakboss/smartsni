echo "DEBUG=1" | sudo tee -a /opt/smartSNI/.env                                                                                                                            
     sudo systemctl restart sni                                                                                                                                                 
     curl -k https://home.shaktt.xyz/ 2>/dev/null                                                                                                                               
     journalctl -u sni -n 15 --no-pager
